"""Draw results/results.png from results/summary.json. Run: uv run python -m bench.chart"""
import json

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

from .common import RESULTS  # noqa: E402

SIGMA, JEV, BOTH = "#2a78d6", "#eb6834", "#1baf7a"
SURFACE, INK, MUTED, GRID = "#fcfcfb", "#0b0b0b", "#52514e", "#e4e3df"


def bars(ax, xs, values, color, width, label):
    b = ax.bar(xs, [v * 100 for v in values], width=width, color=color, label=label, edgecolor=SURFACE, linewidth=2)
    for x, v in zip(xs, values):
        ax.text(x, v * 100 + 2, f"{v:.0%}", ha="center", va="bottom", fontsize=10, color=INK)
    return b


def style(ax, title):
    ax.set_title(title, loc="left", fontsize=11.5, color=INK, pad=12, fontweight="bold")
    ax.set_ylim(0, 112)
    ax.set_yticks([0, 25, 50, 75, 100])
    ax.set_yticklabels(["0", "25", "50", "75", "100%"], color=MUTED, fontsize=9)
    ax.grid(axis="y", color=GRID, linewidth=1)
    ax.set_axisbelow(True)
    ax.tick_params(length=0)
    for s in ax.spines.values():
        s.set_visible(False)
    ax.set_facecolor(SURFACE)


def main():
    s = json.loads((RESULTS / "summary.json").read_text())
    n, c = s["no_rule"], s["changed_text"]
    fig, (a, b) = plt.subplots(1, 2, figsize=(11, 4.4), gridspec_kw={"width_ratios": [1, 1.7]}, facecolor=SURFACE)

    style(a, f"Attacks found when no rule exists for them\n(same false positive rate, {n['sigma_fp']:.1%})")
    bars(a, [0], [n["sigma_recall"]], SIGMA, 0.6, "Sigma rules")
    bars(a, [1], [n["jev_recall"]], JEV, 0.6, "Jev")
    bars(a, [2], [n["both_recall"]], BOTH, 0.6, "Either one")
    a.set_xticks([0, 1, 2])
    a.set_xticklabels(["Sigma\n(other rules)", "Jev\n(generic question)", "Either one"], color=INK, fontsize=9.5)
    a.set_xlim(-0.6, 2.6)

    style(b, "Attacks still found after the command text is changed")
    kinds = [("quotes", 'Inserted quotes\npo""wershell'), ("dash", "Swapped - and /\n(PowerShell)"),
             ("spaces", "Extra spaces"), ("case", "Changed case\n(control)")]
    xs = range(len(kinds))
    bars(b, [x - 0.2 for x in xs], [c[k]["sigma_own_rule"] for k, _ in kinds], SIGMA, 0.4, "Sigma rule for that attack")
    bars(b, [x + 0.2 for x in xs], [c[k]["jev_described"] for k, _ in kinds], JEV, 0.4, "Jev, given the rule's description")
    b.set_xticks(list(xs))
    b.set_xticklabels([f"{lab}\nn={c[k]['n']}" for k, lab in kinds], color=INK, fontsize=9.5)
    b.legend(loc="upper center", bbox_to_anchor=(0.5, -0.28), ncol=2, frameon=False, fontsize=9.5, labelcolor=INK)

    fig.tight_layout(w_pad=4)
    fig.savefig(RESULTS / "results.png", dpi=170, facecolor=SURFACE, bbox_inches="tight")


if __name__ == "__main__":
    main()
