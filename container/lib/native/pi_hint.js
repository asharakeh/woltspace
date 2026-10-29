// Pi extension: deliver a body-free inbox hint into this session as a custom message that starts a turn.
// The attempt directory comes from the launch (WOLTSPACE_NATIVE_DIR). The hint is one file the platform
// writes atomically; claiming it is one rename, so a hint is sent at most once. Never reads mail.
import fs from "node:fs";
import path from "node:path";

const dir = process.env.WOLTSPACE_NATIVE_DIR;
const attempt = process.env.WOLTSPACE_NATIVE_ATTEMPT;

function writeReady() {
  if (fs.existsSync(path.join(dir, "retired"))) return;
  const tmp = path.join(dir, `.ready.json.${process.pid}.tmp`);
  fs.writeFileSync(tmp, JSON.stringify({ kind: "pi-extension", attempt, pid: process.pid }), { mode: 0o600 });
  fs.renameSync(tmp, path.join(dir, "ready.json"));
}

export default function (pi) {
  if (!dir || !attempt) return;
  let timer;
  pi.on("session_start", () => {
    writeReady();
    timer = setInterval(() => {
      const claimed = path.join(dir, `.claimed.${process.pid}`);
      try {
        fs.renameSync(path.join(dir, "hint"), claimed);
      } catch {
        return;
      }
      const text = fs.readFileSync(claimed, "utf8").trim();
      fs.unlinkSync(claimed);
      pi.sendMessage({ customType: "inbox-hint", content: text, display: true }, { triggerTurn: true });
    }, 200);
  });
  pi.on("session_shutdown", () => clearInterval(timer));
}
