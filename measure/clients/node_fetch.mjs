const undici = process.versions.undici || "builtin";
process.stderr.write(undici + "\n");
const r = await fetch(process.argv[2]);
process.stdout.write(await r.text());
