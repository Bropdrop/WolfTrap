# Replay the governed candidate with the draft engines

The governed source descends from Release Trust #25 and Product Foundation #24. The separate WolfNet #22 lineage includes WolfPrint #17, Bloodhound and Cursorial. Qualification joins these histories in a disposable clone. The installed Product Foundation wheel retains its existing scope.

Use a full disposable clone with both parent commits present. Set `candidate` to the independently selected governed PR head. The following commands reproduce the local merge commit used for regression testing. A conflicting merge stops at the tree step and requires review.

```bash
set -euo pipefail
wolfnet=67d66a93c75e3be881953fd31d50ceab88a7815b
tree=$(git merge-tree --write-tree "$wolfnet" "$candidate")
source_date=$(git show -s --format=%cI "$candidate")
combined=$(GIT_AUTHOR_DATE="$source_date" GIT_COMMITTER_DATE="$source_date" \
  git -c user.name="WolfTrap qualification" -c user.email="qualification@example.org" \
  commit-tree "$tree" -p "$wolfnet" -p "$candidate" -m "Disposable governed release and WolfNet qualification")
git switch --detach "$combined"
git rev-parse HEAD 'HEAD^{tree}'
```

Run each qualifier in a fresh loopback-only Linux network namespace with an empty inherited environment, a clean working tree and a separate output directory outside the clone. Acquire the locked build and research prerequisites first. The research qualifier runs full test discovery and independent research replays. Run `scripts/qualify-mcp.py`, `scripts/qualify-cursorial.py`, `scripts/qualify-wolfprint.py`, `scripts/qualify-wolfnet.py` and `scripts/qualify-research.py` with `--expected-head`, `--parent-netns` and `--output-dir`. The product and Release Trust qualifiers also require `--wheelhouse`. The governed qualifier lives at `release/governed_qualification.py`. Run `python -m wolftrap.public_guard "$combined" --workflow-dependencies` against the merged source. [Prerequisites and existing research procedure](release-integration-readiness.md) · [Hosted governed qualification](../.github/workflows/governed-release-qualification.yml)

Review the exact source, both Git trees and individual suite results recorded on the governed PR. Suite-specific case counts overlap with the full regression run. The combined candidate has no distribution, signing or publication authority.
