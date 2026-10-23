import asyncio

from scripter.config import load_config
from scripter.tui.app import ScripterApp, ServiceActionsScreen


def _write_cfg(tmp_path):
    db_path = (tmp_path / "data" / "scripter.db").as_posix()
    log_dir = (tmp_path / "logs").as_posix()
    cfg_path = tmp_path / "config.toml"
    cfg_path.write_text(
        '[scope]\ntargets = ["127.0.0.1"]\n\n'
        f'[storage]\ndb_path = "{db_path}"\n\n'
        f'[logging]\nlog_dir = "{log_dir}"\n\n'
        "[redteam]\nnetwork_audits_enabled = false\n"
    )
    return cfg_path


def test_refresh_redteam_results_works_with_modal_screen_on_top(tmp_path):
    """Regression test for the crash reported when running a red-team tool
    from the Services screen: ServiceActionsScreen._apply_result() calls
    app.refresh_redteam_results(), which used to do self.query_one(...) on
    the App itself. Textual's App.children only ever returns the current
    top-of-stack screen, so once the modal is pushed on top of the
    dashboard, that query_one raised NoMatches on "#redteam_table".
    """
    cfg_path = _write_cfg(tmp_path)
    cfg = load_config(cfg_path)

    async def scenario():
        app = ScripterApp(cfg, cfg_path)
        async with app.run_test() as pilot:
            app.run_id = app.store.start_run(str(cfg_path))
            modal = ServiceActionsScreen(
                host="127.0.0.1",
                port=22,
                service="ssh",
                cfg=cfg,
                run_id=app.run_id,
                store=app.store,
                redteam_store=app.redteam_store,
            )
            app.push_screen(modal)
            await pilot.pause()
            # Must not raise NoMatches even though the modal is on top.
            app.refresh_redteam_results()

    asyncio.run(scenario())
