# Contributing to AlterChat

First off, thank you for considering contributing to AlterChat! It's people like you that make this open-source community such a great place to learn, inspire, and create.

## 1. Where do I go from here?

If you've noticed a bug or have a feature request, make one! It's generally best if you get confirmation of your bug or approval for your feature request this way before starting to code.

## 2. Fork & create a branch

If this is something you think you can fix, then fork AlterChat and create a branch with a descriptive name.

## 3. Implementation Guidelines

- **Security First:** This is a secure messaging application. Any code that touches cryptography, networking, or the SQLite database must be heavily reviewed.
- **No Servers:** Do not introduce any dependency that requires a centralized server.
- **Rust Standards:** Use `cargo fmt` and `cargo clippy` before submitting. Your PR will fail CI if it doesn't pass these checks.
- **Tauri/React Standards:** Keep components small, use functional components, and use strict TypeScript typing.

## 4. Make a Pull Request

At this point, you should switch back to your master branch and make sure it's up to date with AlterChat's master branch:

```sh
git remote add upstream https://github.com/your-org/alterchat.git
git checkout master
git pull upstream master
```

Then update your feature branch from your local copy of master, and push it!

```sh
git checkout 325-add-new-feature
git rebase master
git push --set-upstream origin 325-add-new-feature
```

Finally, go to GitHub and make a Pull Request.
