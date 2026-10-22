// Drive the web portal in a real (headless) browser, like an operator would:
// sign in, open every tab, add and remove a route, sign out.
//
//   ROUTER_URL=https://127.0.0.1:8443/ ADMIN_PASSWORD=... SHOTS=dir node portal-test.mjs
import { writeFile } from "node:fs/promises";
import { chromium } from "playwright";

const url = process.env.ROUTER_URL;
const password = process.env.ADMIN_PASSWORD;
const shots = process.env.SHOTS || ".";
const browser = await chromium.launch();
// The router's certificate is self-signed.
const context = await browser.newContext({ ignoreHTTPSErrors: true });
const page = await context.newPage();
const errors = [];
page.on("pageerror", (e) => errors.push(`page error: ${e.message}`));
// The portal must work under its strict Content-Security-Policy.
page.on("console", (m) => {
  if (m.type() === "error" && /Content Security Policy/i.test(m.text())) errors.push(`CSP: ${m.text()}`);
});
page.on("dialog", (d) => d.accept()); // "Remove route ...?" confirmations
page.setDefaultTimeout(15000);

async function step(name, fn) {
  try {
    await fn();
    console.log(`    ok    ${name}`);
  } catch (e) {
    await page.screenshot({ path: `${shots}/portal-failed.png`, fullPage: true }).catch(() => {});
    // Playwright's call log is long; keep it in the logs, show the gist.
    await writeFile(`${shots}/portal-error.txt`, `${name}\n${e.stack}\n`).catch(() => {});
    throw new Error(`${name}: ${e.message.split("\n").slice(0, 3).join(" | ")}`);
  }
}

try {
  await page.goto(url);
  await step("login page shown", () => page.waitForSelector("#login:not(.hidden) #password"));
  await step("wrong password refused", async () => {
    await page.fill("#password", "definitely-wrong");
    await page.click("#signin");
    await page.waitForSelector("#loginerr:has-text('Wrong')");
  });
  await step("sign in", async () => {
    await page.fill("#password", password);
    await page.click("#signin");
    await page.waitForSelector("#ports td:has-text('lan-a')");
  });
  await step("dashboard shows ports and counters", async () => {
    await page.waitForSelector("#ports td:has-text('lan-b')");
    for (const c of ["Open sessions", "Packets per second", "Throughput", "Dropped packets"]) {
      await page.waitForSelector(`#cards .card:has-text('${c}')`);
    }
    await page.waitForSelector("#wantab td:has-text('lan-b')");
    await page.screenshot({ path: `${shots}/portal-dashboard.png`, fullPage: true });
  });
  await step("reporting tab draws its four graphs", async () => {
    await page.click("button[data-tab=reports]");
    // A locator, not waitForFunction: polling a function means eval in the
    // page, which the portal's Content-Security-Policy (rightly) refuses.
    await page.locator("#charts svg").nth(3).waitFor({ state: "attached" });
    await page.waitForSelector("#ifrates td:has-text('lan-a')");
    await page.waitForSelector("#captab td:has-text('Next hops')");
    await page.waitForSelector("#syscardsr .card:has-text('Memory')");
    await page.screenshot({ path: `${shots}/portal-reporting.png`, fullPage: true });
  });
  await step("sessions tab", async () => {
    await page.click("button[data-tab=sessions]");
    await page.waitForSelector("#sesscount:has-text('sessions')");
  });
  await step("routes tab lists the connected routes", async () => {
    await page.click("button[data-tab=routes]");
    await page.waitForSelector("#rt td:has-text('10.10.1.0/24')");
  });
  // Opening the tab (re)loads the forms; let that finish before typing.
  const openConfig = async () => {
    await page.click("button[data-tab=config]");
    // The portal reopens the last section used, so the interface fields may
    // be loaded but hidden: wait for them to exist, not to be visible.
    await page.waitForSelector("#tab-config[data-ready='1'] #f-ifaces input[data-field=name]", { state: "attached" });
  };
  await step("configuration forms load", async () => {
    await openConfig();
    // The management NIC is listed but never offered to the data plane.
    await page.waitForSelector("#f-nics td:has-text('management: used by the system')");
    await page.click("#cfgnav button[data-sec=nat]");
    await page.waitForSelector("#f-natmain input[type=checkbox]:checked");
    await page.screenshot({ path: `${shots}/portal-config-nat.png`, fullPage: true });
  });
  await step("add a static route with the forms, review, commit", async () => {
    await page.click("#cfgnav button[data-sec=routing]");
    await page.click("#f-routes button:has-text('Add route')");
    await page.locator("#f-routes input[data-field=prefix]").last().fill("192.168.77.0/24");
    await page.locator("#f-routes input[data-field=via]").last().fill("10.10.2.10");
    await page.click("#cfgreview");
    await page.waitForSelector("#msg.ok:has-text('Valid')");
    await page.waitForSelector("#cfgdiff .add:has-text('192.168.77.0/24')");
    await page.screenshot({ path: `${shots}/portal-config-review.png`, fullPage: true });
    await page.click("#cfgcommit");
    await page.waitForSelector("#msg:has-text('Committed')");
    await page.click("button[data-tab=routes]");
    await page.waitForSelector("#rt td:has-text('192.168.77.0/24')");
  });
  await step("invalid input is refused with a reason", async () => {
    await openConfig();
    await page.click("#cfgnav button[data-sec=routing]");
    await page.locator("#f-routes input[data-field=via]").last().fill("172.31.0.1");
    await page.click("#cfgreview");
    await page.waitForSelector("#msg.bad:has-text('not on any connected subnet')");
    await page.click("#cfgdiscard");
    await page.waitForSelector("#cfgstate:has-text('Running configuration')");
  });
  await step("interfaces are edited in one card each", async () => {
    await page.click("#cfgnav button[data-sec=ifaces]");
    await page.waitForSelector("#f-ifaces .card.iface select[data-field=addressing]");
    await page.waitForSelector("#f-ifaces .card.iface input[data-field=mtu]", { state: "attached" });
    if (await page.locator("#cfgnav button:has-text('Internet connection')").count()) throw new Error("the separate Internet connection tab is back");
    // Switching an interface to PPPoE shows its login fields in the same card.
    const last = page.locator("#f-ifaces .card.iface").last();
    await last.locator("select[data-field=addressing]").selectOption("pppoe");
    await page.waitForSelector("#f-ifaces .card.iface input[data-field=username]", { state: "attached" });
    await page.click("#cfgdiscard");
    await page.waitForSelector("#cfgstate:has-text('Running configuration')");
  });
  await step("an interface without a name or card is refused", async () => {
    await page.click("#cfgnav button[data-sec=ifaces]");
    await page.click("#f-ifaces button:has-text('Add interface')");
    await page.click("#cfgreview");
    await page.waitForSelector("#msg.bad:has-text('needs a name')");
    await page.click("#cfgdiscard");
    await page.waitForSelector("#cfgstate:has-text('Running configuration')");
  });
  await step("remove the route with the forms", async () => {
    await page.click("#cfgnav button[data-sec=routing]");
    await page.locator("#f-routes button:has-text('Remove')").last().click(); // the only static route
    await page.click("#cfgreview");
    await page.waitForSelector("#cfgdiff .del:has-text('192.168.77.0/24')");
    await page.click("#cfgcommit");
    await page.waitForSelector("#msg:has-text('Committed')");
    await page.click("button[data-tab=routes]");
    await page.waitForSelector("#rt td:has-text('192.168.77.0/24')", { state: "detached" });
  });
  await step("system tab shows the build", async () => {
    await page.click("button[data-tab=system]");
    await page.waitForSelector("#syscards .card:has-text('Running version')");
    await page.screenshot({ path: `${shots}/portal-system.png`, fullPage: true });
  });
  await step("sign out", async () => {
    await page.click("#logout");
    await page.waitForSelector("#login:not(.hidden)");
  });
  if (errors.length) throw new Error(errors.join("; "));
} finally {
  await browser.close();
}
