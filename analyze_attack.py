"""
analyze_attack.py - Attack timeline chart for Project 4 (Network Forensics)

Usage:
    python3 analyze_attack.py packets.csv

Input: Wireshark CSV export (File -> Export Packet Dissections -> As CSV)
       with at least "Time" and "Protocol" columns ("Info" is optional but
       lets the script suggest where the exploitation phase begins).

Output: attack_timeline.png (README / report ready) + a printed summary table.
"""
import sys
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from matplotlib.ticker import FuncFormatter, NullLocator

# ── 1. PHASE BOUNDARIES (seconds into capture) ──────────────────────────────
# Read these off Wireshark's Time column, then edit.
# The script prints suggested values from your data so you can sanity-check.
RECON_END     = 200      # last Nmap packet
BRUTE_END     = 5630     # packet 185060: RST,ACK that ends the SSH session
EXPLOIT_END   = 5834     # last FTP / port 6200 packet

PHASES = [
    # key,       label,              MITRE,   colour
    ("recon",   "Reconnaissance",   "T1046", "#2a78d6"),   # blue
    ("brute",   "Brute Force",      "T1110", "#eb6834"),   # orange
    ("exploit", "Exploitation",     "T1190", "#1baf7a"),   # aqua
]
OTHER_COLOUR = "#b9b8b2"

# ── Surface / text tokens (light) ───────────────────────────────────────────
SURFACE = "#fcfcfb"
INK     = "#0b0b0b"
INK_2   = "#52514e"
GRID    = "#e6e5e0"

# ── 2. LOAD ─────────────────────────────────────────────────────────────────
path = sys.argv[1] if len(sys.argv) > 1 else "packets.csv"
try:
    df = pd.read_csv(path)
except FileNotFoundError:
    sys.exit(f"{path} not found - export from Wireshark first "
             "(File -> Export Packet Dissections -> As CSV)")

df.columns = [c.strip().lower().replace(" ", "_") for c in df.columns]
df["time"] = pd.to_numeric(df["time"], errors="coerce")
df = df.dropna(subset=["time"])
df["time"] = df["time"] - df["time"].min()          # always start at 0
proto_col = "protocol" if "protocol" in df.columns else None
if proto_col is None:
    df["protocol"] = "Unknown"

# ── 3. SUGGEST BOUNDARIES FROM THE DATA (printed, not applied) ──────────────
print("\n-- Boundary hints (compare with the values at the top of this file) --")
ssh = df[df["protocol"].str.upper().str.startswith("SSH")]
if not ssh.empty:
    print(f"  first SSH packet : {ssh['time'].min():8.1f}s   (brute force starts about here)")
    print(f"  last  SSH packet : {ssh['time'].max():8.1f}s   (brute force ends about here)")
if "info" in df.columns:
    trig = df[df["info"].astype(str).str.contains(r"USER .*:\)", regex=True)]
    if not trig.empty:
        print(f"  vsftpd ':)' USER: {trig['time'].min():8.1f}s   (exploitation starts here)")
print(f"  capture length   : {df['time'].max():8.1f}s")

# ── 4. LABEL PHASES ─────────────────────────────────────────────────────────
t = df["time"]
df["phase"] = np.select(
    [t < RECON_END, (t >= RECON_END) & (t < BRUTE_END), (t >= BRUTE_END) & (t <= EXPLOIT_END)],
    ["recon", "brute", "exploit"],
    default="other",
)

# ── 5. FIGURE ───────────────────────────────────────────────────────────────
plt.rcParams.update({
    "font.family": "DejaVu Sans",
    "text.color": INK, "axes.labelcolor": INK_2,
    "xtick.color": INK_2, "ytick.color": INK_2,
    "axes.edgecolor": GRID,
})
fig = plt.figure(figsize=(14, 10.5), facecolor=SURFACE)
gs = fig.add_gridspec(3, 3, height_ratios=[0.8, 2.6, 2.2],
                      hspace=0.42, wspace=0.40,
                      left=0.06, right=0.97, top=0.88, bottom=0.04)

fig.text(0.06, 0.955, "Attack Traffic Timeline", fontsize=20, fontweight="bold", ha="left")
fig.text(0.06, 0.918,
         "Kali (192.168.56.101) → Metasploitable2 (192.168.56.102)  ·  three phases in one capture  ·  MITRE ATT&CK mapped",
         fontsize=11, color=INK_2, ha="left")

# ---- Row 1: one summary tile per phase -------------------------------------
fmt_n = lambda n: f"{int(n):,}"
def fmt_dur(s):
    s = float(s)
    return f"{s:.0f} s" if s < 120 else f"{s/60:.0f} min"

for i, (key, label, mitre, colour) in enumerate(PHASES):
    ax = fig.add_subplot(gs[0, i])
    ax.set_facecolor(SURFACE)
    ax.axis("off")
    sub = df[df["phase"] == key]
    ax.add_patch(plt.Rectangle((0, 0), 0.012, 1, transform=ax.transAxes,
                               color=colour, clip_on=False))
    ax.text(0.05, 0.92, f"PHASE {i+1}  ·  {mitre}", fontsize=9, color=INK_2,
            va="top", transform=ax.transAxes)
    ax.text(0.05, 0.68, label, fontsize=15, fontweight="bold", va="top", transform=ax.transAxes)
    if sub.empty:
        ax.text(0.05, 0.30, "no packets in range", fontsize=10, color=INK_2, transform=ax.transAxes)
        continue
    # robust span: ignore the few stray packets at the very start/end of a phase
    active = sub["time"].quantile(0.995) - sub["time"].quantile(0.005)
    ax.text(0.05, 0.30, f"{fmt_n(len(sub))} packets", fontsize=12, va="center", transform=ax.transAxes)
    ax.text(0.05, 0.08, f"active for {fmt_dur(active)}", fontsize=10, color=INK_2,
            va="center", transform=ax.transAxes)

# ---- Row 2: timeline, log y-axis -------------------------------------------
ax = fig.add_subplot(gs[1, :])
ax.set_facecolor(SURFACE)
BIN = 20
df["bin"] = (df["time"] // BIN) * BIN
colours = {k: c for k, _, _, c in PHASES}
colours["other"] = OTHER_COLOUR

for key in ["other", "recon", "brute", "exploit"]:
    counts = df[df["phase"] == key].groupby("bin").size()
    if counts.empty:
        continue
    ax.bar(counts.index + BIN / 2, counts.values, width=BIN * 0.9,
           color=colours[key], linewidth=0, zorder=3)

ax.set_yscale("log")
ax.set_ylim(0.8, df.groupby("bin").size().max() * 4)
ax.set_xlim(-BIN, df["time"].max() + 900)      # right padding leaves room for the exploit label
ax.yaxis.set_major_formatter(FuncFormatter(lambda v, _: f"{int(v):,}"))
ax.set_ylabel("Packets per 20 s  (log scale)", fontsize=10)
ax.set_xlabel("Seconds into capture", fontsize=10)
ax.grid(axis="y", color=GRID, linewidth=0.8, zorder=0)
for s in ("top", "right", "left"):
    ax.spines[s].set_visible(False)
ax.tick_params(length=0)
ax.yaxis.set_minor_locator(NullLocator())
ax.set_title("Packet volume- the scan is loud, the brute force is long, the exploit is brief",
             fontsize=12, loc="left", pad=10, color=INK)

# Phase boundaries + direct labels
peak = df.groupby("bin").size().max()
for x in (RECON_END, BRUTE_END):
    ax.axvline(x, color=INK_2, linestyle=(0, (4, 3)), linewidth=1, zorder=2)

# Direct labels (kept inside the plot area, clear of the bars)
ax.text(RECON_END + 60, peak * 0.55, "Recon: Nmap -sV -A -p-", ha="left", va="center",
        fontsize=10, fontweight="bold", color=colours["recon"])
brute_mid = (RECON_END + BRUTE_END) / 2
ax.text(brute_mid, 3000, "SSH brute force (T1110): steady, automated attempts",
        ha="center", va="center", fontsize=10, fontweight="bold", color=colours["brute"])
ax.text(BRUTE_END + 60, peak * 0.55, "vsftpd\nbackdoor", ha="left", va="center",
        fontsize=10, fontweight="bold", color=colours["exploit"])

# Annotate the end of the successful SSH session
ax.annotate("Successful SSH session ends\n(packet 185060, RST,ACK)",
            xy=(BRUTE_END, 400), xytext=(BRUTE_END - 250, 1200),
            fontsize=9, color=INK_2, ha="right", va="center",
            arrowprops=dict(arrowstyle="-", color=INK_2, linewidth=0.8))

# ---- Row 3: top protocols per phase ----------------------------------------
TOP_N = 5
for i, (key, label, mitre, colour) in enumerate(PHASES):
    ax = fig.add_subplot(gs[2, i])
    ax.set_facecolor(SURFACE)
    sub = df[df["phase"] == key]
    ax.set_title(f"{label}: what was on the wire", fontsize=11, loc="left", pad=8)
    if sub.empty:
        ax.axis("off")
        continue
    vc = sub["protocol"].value_counts()
    top = vc.head(TOP_N)
    rest = vc.iloc[TOP_N:].sum()
    if rest > 0:
        top = pd.concat([top, pd.Series({"Other": rest})])
    share = top / len(sub) * 100
    y = np.arange(len(share))[::-1] + (TOP_N + 1 - len(share))   # top-aligned
    ax.set_ylim(-0.6, TOP_N + 0.6)                               # same bar height in every panel
    bar_colours = [colour if p != "Other" else OTHER_COLOUR for p in share.index]
    # Bar length is log-scaled so minor protocols stay visible next to a dominant one
    # (e.g. 133k TCP vs 49 TLSv1). Labels always show the true share and count.
    length = np.log10(top.values + 1) / np.log10(top.values.max() + 1) * 100
    ax.barh(y, length, height=0.62, color=bar_colours, linewidth=0, zorder=3)
    ax.set_yticks(y)
    ax.set_yticklabels(share.index, fontsize=10, color=INK)
    ax.set_xlim(0, 150)
    ax.set_xticks([])
    for yi, l, (p, s) in zip(y, length, share.items()):
        pct = f"{s:.0f}%" if s >= 1 else "<1%"
        ax.text(l + 2, yi, f"{pct}  ·  {fmt_n(top[p])}", va="center",
                fontsize=9, color=INK_2)
    for sp in ("top", "right", "bottom", "left"):
        ax.spines[sp].set_visible(False)
    ax.tick_params(length=0)

fig.text(0.06, 0.012, "Protocol bars are log-scaled so minor protocols stay visible; labels show the true share and packet count.",
         fontsize=8.5, color=INK_2, ha="left")
fig.savefig("attack_timeline.png", dpi=200, facecolor=SURFACE)
print("\nSaved attack_timeline.png")

# ── 6. SUMMARY TABLE ────────────────────────────────────────────────────────
print("\n-- Attack phase summary --------------------------------------------")
rows = []
for key, label, mitre, _ in PHASES + [("other", "Other", "-", None)]:
    sub = df[df["phase"] == key]
    if sub.empty:
        continue
    rows.append({
        "phase": label, "mitre": mitre, "packets": len(sub),
        "start_s": round(sub["time"].min(), 1), "end_s": round(sub["time"].max(), 1),
        "top_protocol": sub["protocol"].value_counts().index[0],
    })
print(pd.DataFrame(rows).to_string(index=False))
