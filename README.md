# Public GitHub observation study

Incremental preservation of public repository observations, with independently verifiable evidence and external timestamps.

- [Current requirements](requirements.md)
- [Collector and usage](icsot-observatory/README.md)
- [Design](icsot-observatory/docs/DESIGN.md)
- [SQLite schema](icsot-observatory/docs/SCHEMA.md)

The first target is [`libfuse/libfuse`](https://github.com/libfuse/libfuse), configured in [config.libfuse.toml](icsot-observatory/config.libfuse.toml).

The collector is a prototype. SQLite integration, native XZ storage, first-observed commit queries, GitHub Discussions and interval commits in a study Git repository remain implementation work. Source control excludes collected evidence and credentials. The manual Actions smoke test uses temporary artifacts; its evidence must be copied to durable storage for indefinite retention. No recurring collection schedule is enabled yet.
