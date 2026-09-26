# What This Is, and Why I Built It

I was set a challenge: with AI as good as it now is, could someone figure out and reproduce what a specialist does day in and day out as their job — a job that isn't mine? The specialist here is a network engineer. I'm not one. So I built a working network operations tool to prove I could learn the job well enough to do a real slice of it, and stand behind the result.

This is that tool. It's live, anyone can use it, and it's tested.

## What a network engineer actually does

Strip the job to its core and it's three things, repeated all day:

1. **Watch the network** — is everything up, what's running hot, what changed.
2. **Diagnose it** — someone says "I can't reach the server," and you work out why, fast.
3. **Audit and fix the setup** — check the device configurations for mistakes and security holes, and correct them.

I built a tool that does a real piece of all three, working from actual Cisco device configuration files.

## How the tool maps to the job

**Reading the configs.** Every network device has a configuration file — a long text document listing every port, address, and rule. Engineers live in these files. The tool reads them the way an engineer does and turns them into something it can reason about. If it hits a line it doesn't understand, it flags it rather than quietly ignoring it — because silently skipping something is how real mistakes slip through.

**Drawing the map.** Nobody hands you a diagram of an unfamiliar network — you work out what connects to what from the configs. The tool does the same, two ways: matching up addresses, and reading the labels on each connection. And when it finds two devices both claiming to own the same stretch of the network, it doesn't pretend they're connected — it flags it as a conflict. Knowing the difference between "these are linked" and "these are misconfigured to look linked" is exactly the judgment the job needs.

**The audit — checking the work.** The tool inspects every device against a checklist a senior engineer carries in their head: is remote access using an insecure method, are the passwords weak, is a server accidentally cut off, do two devices clash. For each problem it says three things: what's wrong, why it matters, and the exact commands to fix it. Anyone can search a file for the word "telnet." Knowing that telnet is dangerous because it sends your password in plain text for anyone to read — that's the difference between running a script and understanding the job.

**The live view.** A dashboard shows the network as if it were running — every connection up or down, how busy each one is, what's raising an alarm. You can break a link on purpose and watch the alerts fire, the way you'd see a real outage land.

**The troubleshooter — the heart of it.** This is the part I'm proudest of. You type a problem — "this server can't reach its gateway" — and the tool works through it the way a good engineer does: from the bottom up. Is the cable alive? Is it in the right group? Is there a route? Is a rule blocking it? It checks in that order and stops at the first thing that's actually broken, because that's the real cause — everything above it is just a symptom. Then it tells you the fix.

While building it I hit a moment that convinced me the tool genuinely worked. I expected a certain fault to trace to one place. The tool disagreed and pointed somewhere else — and it was right, because following the logic honestly led there, not to where I'd assumed. It didn't bend the answer to match what I expected. That's not a tool doing a trick. That's a tool doing the reasoning.

## What's real and what's simulated

I'll be straight about this, because it's the honest part that makes the rest credible. There's no real network behind this — the live view is simulated, because I don't have a rack of routers to plug into. But the hard part — reading real configuration files, auditing them, mapping the network, and reasoning through a fault layer by layer — is real. Point it at any Cisco config in the standard format and it does the same work.

## The point

I'm not a network engineer. I didn't spend years learning this. But working with AI, in one focused effort, I learned enough of the discipline to build a working tool that does the real job — and, just as important, I tested it hard enough to trust it in front of someone who does know networks. I found my own mistakes before they did. That's the point the challenge was meant to make, and I think the tool makes it.

**See it:** [mini-nms.onrender.com](https://mini-nms.onrender.com)
