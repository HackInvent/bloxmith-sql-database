"""FB7: real release UI in managed and linked hosts: conditional fields, drafts, validation, EN/FR, responsive geometry."""

import json
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[3]
sys.path[:0] = [str(ROOT), str(ROOT / "tests")]
from playwright.sync_api import TimeoutError as PlaywrightTimeoutError, expect, sync_playwright
SETTLE_MS = 15000  # Shared test hosts can be slow; assertions still fail on real defects.
expect.set_options(timeout=SETTLE_MS)
from block_test_artifacts import artifact_path
from block_test_packages import install_test_package, surface_payload
from ui_smoke_common import isolated_server, graph_payload, create_project_api, project_editor_url
from blocs.sql_database.block import SqlDatabaseBlock

MEASURE = """(el, bodySelector) => {
    const r=el.getBoundingClientRect(), body=el.querySelector(bodySelector) || el;
    const actions=[...el.querySelectorAll('[data-close-block-modal], [data-owned-apply]')];
    return {inside:r.left>=-1&&r.right<=innerWidth+1&&r.top>=-1&&r.bottom<=innerHeight+1,
      overflow:el.scrollWidth>el.clientWidth+2||body.scrollWidth>body.clientWidth+2,
      controls:actions.every(a=>{const b=a.getBoundingClientRect();return b.top>=0&&b.bottom<=innerHeight+1}),
      background:getComputedStyle(el).backgroundColor,
      unlabeled:[...el.querySelectorAll('input,select,textarea')].filter(c=>!c.labels?.length&&!c.getAttribute('aria-label')&&!c.getAttribute('aria-labelledby')).length};
}"""


def geometry_ok(measured):
    return (measured["inside"] and measured["controls"] and not measured["overflow"] and not measured["unlabeled"]
            and measured["background"] not in {"transparent", "rgba(0, 0, 0, 0)"})


def resize(page, width, height):
    """Resize, then wait until the page reports the new viewport and has painted twice."""
    page.set_viewport_size({"width": width, "height": height})
    page.wait_for_function("([w, h]) => innerWidth === w && innerHeight === h", arg=[width, height], timeout=SETTLE_MS)
    page.evaluate("() => new Promise(done => requestAnimationFrame(() => requestAnimationFrame(done)))")


def geometry(surface, body=".owned-body"):
    """Require an opaque panel with reachable actions, labelled controls and no horizontal overflow.

    The editor re-lays the modal out after a resize (compact view, responsive rules), so the
    condition is polled until it holds or the settle timeout expires; a real layout defect
    persists and fails with the last measurement.
    """
    deadline = time.monotonic() + SETTLE_MS / 1000
    measured = surface.evaluate(MEASURE, body)
    while not geometry_ok(measured) and time.monotonic() < deadline:
        surface.page.wait_for_timeout(100)
        measured = surface.evaluate(MEASURE, body)
    assert measured["inside"] and measured["controls"] and not measured["overflow"], measured
    assert not measured["unlabeled"], measured
    assert measured["background"] not in {"transparent", "rgba(0, 0, 0, 0)"}, measured


def field(surface, key):
    return surface.locator(f'[data-block-config-field="{key}"]')


def open_modal(card, modal):
    """Open the modal from the canvas card; after a reload the editor may bind its handlers late."""
    expect(card.locator('h3')).to_be_visible(timeout=30000)
    for _ in range(6):
        if modal.is_visible():
            return
        try:
            card.locator('h3').dblclick(timeout=5000)
            expect(modal).to_be_visible(timeout=5000)
            return
        except (AssertionError, PlaywrightTimeoutError):
            continue
    expect(modal).to_be_visible()


def main():
    """Exercise the current package files through the real managed and linked browser hosts."""
    for origin in ("managed", "linked"):
        with isolated_server() as server, sync_playwright() as playwright:
            model = install_test_package(server, "sql_database", origin=origin)
            candidate = SqlDatabaseBlock().build_node_payload(node_id="ui-case", position={"x": 160, "y": 160})
            candidate["block_version"] = model["version"]
            # - FB7 - Every surface declares its assets and a complete EN/FR catalog for its markers.
            for surface in ("modal", "inspector_panel", "node_card"):
                payload = surface_payload(server, model, candidate, surface=surface)
                assert "{{" not in payload["html"] and set(payload["locales"]) >= {"en", "fr"}
            project = create_project_api(server, document=graph_payload("SQL settings", [candidate], []))["project"]
            url = project_editor_url(server.base_url, project["project_id"], workspace_project_id=project["workspace_project_id"])
            browser = playwright.chromium.launch(headless=True)
            try:
                page = browser.new_page(viewport={"width": 1440, "height": 900})
                page.add_init_script("window.localStorage.setItem('bloxsmith.inspectorPinned','true')")
                errors = []
                page.on("pageerror", lambda error: errors.append(str(error)))
                page.goto(url)
                card = page.locator('.canvas-node[data-node-id="ui-case"]')
                expect(card.locator('h3')).to_be_visible()
                expect(card.locator('.node-data-preview')).to_contain_text("sqlite · query")
                modal = page.locator('.owned-modal')
                apply = modal.locator('[data-owned-apply]')
                open_modal(card, modal)
                expect(apply).to_be_disabled()
                # Driver- and operation-specific fields follow the draft without leaving the form.
                expect(field(modal, "sql")).to_be_visible()
                expect(field(modal, "sqlite_file")).to_be_visible()
                for key in ("pg_host", "pg_password_ref", "table", "columns", "conflict_columns"):
                    expect(field(modal, key)).to_be_hidden()
                field(modal, "driver").select_option("postgresql")
                expect(field(modal, "pg_host")).to_be_visible()
                expect(field(modal, "pg_password_ref")).to_be_visible()
                expect(field(modal, "sqlite_file")).to_be_hidden()
                field(modal, "operation").select_option("upsert")
                for key in ("table", "columns", "conflict_columns", "update_columns"):
                    expect(field(modal, key)).to_be_visible()
                expect(field(modal, "sql")).to_be_hidden()
                expect(apply).to_be_enabled()
                page.screenshot(path=artifact_path(f"sql_database-{origin}-postgresql-upsert.png"))
                # Cancel discards the draft.
                modal.locator('[data-close-block-modal]').last.click()
                open_modal(card, modal)
                expect(field(modal, "driver")).to_have_value("sqlite")
                expect(field(modal, "operation")).to_have_value("query")
                expect(field(modal, "pg_host")).to_be_hidden()
                # An unsafe draft is refused by the server and nothing is persisted.
                field(modal, "operation").select_option("execute")
                field(modal, "sql").fill("DELETE FROM items")
                with page.expect_response(lambda r: r.url.endswith('/ui-action') and r.request.method == 'POST'):
                    apply.click()
                expect(modal.locator('.owned-form-status')).to_contain_text("allow_writes")
                modal.locator('[data-close-block-modal]').first.click()
                page.reload()
                open_modal(card, modal)
                expect(field(modal, "operation")).to_have_value("query")
                expect(field(modal, "sql")).to_have_value("SELECT 1 AS ok")
                # A valid draft is applied and survives a reload.
                field(modal, "sql").fill("SELECT sku FROM items WHERE stock >= :low")
                modal.locator('.owned-advanced').first.locator('summary').click()
                field(modal, "max_rows").fill("50")
                with page.expect_response(lambda r: r.url.endswith('/ui-action') and r.request.method == 'POST') as saved:
                    apply.click()
                assert not saved.value.json().get("error"), saved.value.json()
                expect(modal.locator('.owned-form-status')).to_contain_text("Settings applied")
                if modal.is_visible():
                    modal.locator('[data-close-block-modal]').first.click()
                page.reload()
                open_modal(card, modal)
                expect(field(modal, "sql")).to_have_value("SELECT sku FROM items WHERE stock >= :low")
                expect(field(modal, "max_rows")).to_have_value("50")
                assert json.loads(field(modal, "statements").input_value()) == {}
                for width, height in ((1440, 900), (800, 700), (390, 740), (320, 568)):
                    resize(page, width, height)
                    geometry(modal)
                    page.screenshot(path=artifact_path(f"sql_database-{origin}-{width}.png"))
                summary = modal.locator('.owned-advanced').first.locator('summary')
                summary.scroll_into_view_if_needed()
                summary.focus()
                summary.press('Enter')
                expect(modal.locator('.owned-advanced').first).to_have_attribute('open', '')
                expect(field(modal, "timeout_sec")).to_be_visible()
                geometry(modal)
                page.screenshot(path=artifact_path(f"sql_database-{origin}-advanced.png"))
                resize(page, 1440, 900)
                modal.locator('[data-close-block-modal]').first.click()
                # The inspector exposes the same fields, conditions and Ports tab.
                card.click(position={"x": 20, "y": 20})
                inspector = page.locator('[data-properties-surface="inspector"][data-node-id="ui-case"]:visible')
                expect(inspector).to_be_visible()
                assert inspector.evaluate('el => el.scrollWidth <= el.clientWidth+2')
                expect(field(inspector, "sql")).to_have_value("SELECT sku FROM items WHERE stock >= :low")
                field(inspector, "driver").select_option("postgresql")
                expect(field(inspector, "pg_sslmode")).to_be_visible()
                expect(inspector.locator('[data-owned-apply]')).to_be_enabled()
                inspector.locator('[data-inspector-tab="ports"]').click()
                expect(inspector.locator('[data-inspector-panel-tab="ports"]')).to_be_visible()
                inspector.locator('[data-inspector-tab="general"]').click()
                expect(inspector.locator('[data-inspector-panel-tab="general"]')).to_be_visible()
                page.screenshot(path=artifact_path(f"sql_database-{origin}-inspector.png"))
                for width, height in ((390, 740), (320, 568)):
                    resize(page, width, height)
                    page.screenshot(path=artifact_path(f"sql_database-{origin}-inspector-{width}.png"))
                resize(page, 1440, 900)
                # French interface: block texts come from the package catalog.
                page.goto(server.base_url + "/")
                page.locator("#homeApplicationSettingsButton").click()
                page.locator("#applicationLanguageSelect").select_option("fr")
                page.wait_for_function("window.CWMessages.getLanguage() === 'fr'")
                page.goto(url)
                open_modal(card, modal)
                expect(modal.locator('.owned-advanced').first.locator('summary')).to_have_text("Réglages avancés")
                expect(modal.locator('.panel-kicker')).to_have_text("Base de données")
                expect(modal.locator(f'#{field(modal, "driver").get_attribute("aria-describedby")}')).to_contain_text("stockage de ce nœud")
                resize(page, 390, 740)
                geometry(modal)
                page.screenshot(path=artifact_path(f"sql_database-{origin}-fr-390.png"))
                assert not errors, errors
                assert page.evaluate("!window.CWBlockUiBlocks?.sql_database")
            finally:
                browser.close()
        print("[ok] sql_database " + origin + " UI", flush=True)


if __name__ == "__main__":
    main()
