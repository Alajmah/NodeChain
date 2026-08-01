"""v2.79 — Click declaration modules for relocated command groups.

This subpackage holds the Click @cli.group/@cli.command declarations that
were previously inline in cli/main.py. Each module imports implementation
functions lazily from the sibling cli/*.py modules (preserving the
import-is-lightweight property) and exports a register(cli) function that
main.py calls to wire the group into the root Click command.

Pattern per module:
    @click.group("evidence")
    def evidence_group(): ...

    @evidence_group.command("show")
    @click.option(...)
    def show(...):
        from nodechain.cli.evidence import show_evidence  # LAZY
        return show_evidence(...)

    def register(cli):
        cli.add_command(evidence_group)
"""
