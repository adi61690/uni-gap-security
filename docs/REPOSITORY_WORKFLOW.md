# Team Git Workflow

1. Clone the repository.
2. Create a feature branch: `git switch -c feature/<short-name>`.
3. Make changes only in the relevant role folder.
4. Run that component's tests/build before committing.
5. Commit with a descriptive message.
6. Push the branch and open a Pull Request.
7. Another teammate reviews the PR.
8. Merge to `main` only after checks pass.

Do not commit secrets, `.env` files, virtual environments, `node_modules`, generated PCAPs, or local databases.
