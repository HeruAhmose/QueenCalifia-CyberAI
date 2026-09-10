import fs from "node:fs/promises";
import { chromium } from "playwright";

const baseURL = "http://127.0.0.1:4173/QueenCalifia-CyberAI/";
const evidenceDir = "qc-identity-evidence";
await fs.mkdir(evidenceDir, { recursive: true });

const browser = await chromium.launch({ headless: true });
const viewports = {
  desktop: { width: 1440, height: 1000 },
  mobile: { width: 390, height: 844 },
};

const report = { generatedAt: new Date().toISOString(), viewports: {}, reducedMotion: null };
let failures = 0;

async function waitForPortrait(page, state, expectedFile) {
  const alt = `Queen Califia — ${state}`;
  const image = page.locator(`img[alt="${alt}"]`).first();
  await image.waitFor({ state: "visible", timeout: 10000 });
  await page.waitForFunction(
    ({ altText, filename }) => {
      const img = [...document.images].find((node) => node.alt === altText);
      return Boolean(
        img?.complete &&
        img.naturalWidth > 0 &&
        img.naturalHeight > 0 &&
        new URL(img.currentSrc || img.src, location.href).pathname.endsWith(`/qc-assets/${filename}`)
      );
    },
    { altText: alt, filename: expectedFile },
    { timeout: 10000 },
  );
  return image;
}

for (const [name, viewport] of Object.entries(viewports)) {
  const context = await browser.newContext({ viewport, reducedMotion: "no-preference" });
  const page = await context.newPage();
  const pageErrors = [];
  const criticalFailures = [];
  page.on("pageerror", (error) => pageErrors.push(String(error)));
  page.on("requestfailed", (request) => {
    if (["document", "script", "stylesheet", "image", "font"].includes(request.resourceType())) {
      criticalFailures.push({ url: request.url(), type: request.resourceType(), error: request.failure()?.errorText });
    }
  });

  const result = { hardFailure: false, error: null };
  try {
    const response = await page.goto(baseURL, { waitUntil: "domcontentloaded", timeout: 30000 });
    result.navStatus = response?.status() ?? null;
    if (!response?.ok()) throw new Error(`navigation status ${response?.status()}`);

    const faviconHrefs = await page.locator('link[rel~="icon"]').evaluateAll((nodes) => nodes.map((node) => node.href));
    const appleTouchHref = await page.locator('link[rel="apple-touch-icon"]').getAttribute("href");
    const manifestHref = await page.locator('link[rel="manifest"]').getAttribute("href");
    result.faviconHrefs = faviconHrefs;
    result.appleTouchHref = appleTouchHref;
    result.manifestHref = manifestHref;
    if (!faviconHrefs.some((href) => href.includes("/QueenCalifia-CyberAI/qc-assets/branding/sigil/sigil_icon_32.png"))) {
      throw new Error("32px sovereign sigil favicon is not bound to the Pages base path");
    }
    if (!faviconHrefs.some((href) => href.includes("/QueenCalifia-CyberAI/qc-assets/branding/sigil/sigil_icon_512.png"))) {
      throw new Error("512px sovereign sigil favicon is not bound to the Pages base path");
    }
    if (!appleTouchHref?.includes("/QueenCalifia-CyberAI/qc-assets/branding/sigil/sigil_icon_512.png")) {
      throw new Error("apple-touch-icon is not bound to the sovereign sigil");
    }
    if (!manifestHref?.includes("/QueenCalifia-CyberAI/manifest.json")) throw new Error("web manifest path is not portable");
    for (const href of [...faviconHrefs, appleTouchHref, manifestHref].filter(Boolean)) {
      const absoluteHref = new URL(href, page.url()).href;
      const assetResponse = await context.request.get(absoluteHref);
      if (!assetResponse.ok()) throw new Error(`identity metadata asset returned ${assetResponse.status()}: ${absoluteHref}`);
    }

    const awakening = page.locator(".qc-sovereign-awakening");
    await awakening.waitFor({ state: "visible", timeout: 10000 });
    if ((await awakening.getAttribute("data-qc-awakening-phase")) !== "sealed") throw new Error("awakening did not start sealed");
    if ((await awakening.getAttribute("data-qc-awakening-avatar-state")) !== "idle") throw new Error("sealed phase is not mapped to idle portrait");
    const idleImage = await waitForPortrait(page, "idle", "idle_avatar_sm.png");
    result.idleSrc = await idleImage.getAttribute("src");

    const ringAnimation = await page.locator(".qc-ring-spin").first().evaluate((node) => getComputedStyle(node).animationName);
    const scanAnimation = await page.locator(".qc-awaken-holo-scan").evaluate((node) => getComputedStyle(node).animationName);
    result.ringAnimation = ringAnimation;
    result.scanAnimation = scanAnimation;
    if (!ringAnimation.includes("qc-rotate")) throw new Error(`avatar orbit animation inactive: ${ringAnimation}`);
    if (!scanAnimation.includes("qc-awaken-holo-scan")) throw new Error(`holographic scan animation inactive: ${scanAnimation}`);

    await page.getByRole("button", { name: "AWAKEN SOVEREIGN INTELLIGENCE" }).click();
    await page.waitForFunction(() => document.querySelector(".qc-sovereign-awakening")?.dataset.qcAwakeningPhase === "linking", null, { timeout: 5000 });
    const activeImage = await waitForPortrait(page, "active", "active_avatar_sm.png");
    result.activeSrc = await activeImage.getAttribute("src");

    await page.waitForFunction(() => document.querySelector(".qc-sovereign-awakening")?.dataset.qcAwakeningPhase === "authorized", null, { timeout: 5000 });
    const authorityImage = await waitForPortrait(page, "staff_raised", "staff_raised_avatar_sm.png");
    result.authoritySrc = await authorityImage.getAttribute("src");
    await page.getByRole("button", { name: "ENTER COMMAND FIELD" }).click();

    await page.waitForFunction(() => document.querySelector(".qc-sovereign-awakening")?.dataset.qcAwakeningPhase === "entering", null, { timeout: 3000 });
    const ascendedImage = await waitForPortrait(page, "ascended", "ascended_avatar_sm.png");
    result.ascendedSrc = await ascendedImage.getAttribute("src");
    await page.screenshot({ path: `${evidenceDir}/${name}-awakening-ascended.png`, fullPage: true });

    await page.locator('[data-qc-command-frame="prestige-v1"]').waitFor({ state: "visible", timeout: 10000 });
    await page.waitForTimeout(1200);
    const commandPortraitCount = await page.locator('img[alt*="Queen Califia"]').count();
    const brokenImages = await page.locator("img").evaluateAll((imgs) => imgs.filter((img) => img.complete && img.naturalWidth === 0).map((img) => img.currentSrc || img.src));
    const overflow = await page.evaluate(() => Math.max(0, document.documentElement.scrollWidth - document.documentElement.clientWidth));
    result.commandPortraitCount = commandPortraitCount;
    result.brokenImages = brokenImages;
    result.horizontalOverflowPx = overflow;
    result.pageErrors = pageErrors;
    result.failedCriticalRequests = criticalFailures;
    if (commandPortraitCount < 1) throw new Error("Queen Califia portrait disappeared after command-field handoff");
    if (brokenImages.length) throw new Error(`broken images after handoff: ${brokenImages.join(", ")}`);
    if (overflow > 1) throw new Error(`horizontal overflow ${overflow}px`);
    if (pageErrors.length) throw new Error(`page errors: ${pageErrors.join(" | ")}`);
    if (criticalFailures.length) throw new Error(`critical request failures: ${criticalFailures.map((x) => x.url).join(", ")}`);
    await page.screenshot({ path: `${evidenceDir}/${name}-command-field.png`, fullPage: true });
  } catch (error) {
    failures += 1;
    result.hardFailure = true;
    result.error = String(error);
    await page.screenshot({ path: `${evidenceDir}/${name}-failure.png`, fullPage: true }).catch(() => {});
  }
  report.viewports[name] = result;
  console.log("QC_IDENTITY_RESULT " + JSON.stringify({ viewport: name, ...result }));
  await context.close();
}

{
  const context = await browser.newContext({ viewport: viewports.mobile, reducedMotion: "reduce" });
  const page = await context.newPage();
  await page.emulateMedia({ reducedMotion: "reduce" });
  const pageErrors = [];
  page.on("pageerror", (error) => pageErrors.push(String(error)));
  const result = { hardFailure: false, error: null };
  try {
    const response = await page.goto(baseURL, { waitUntil: "domcontentloaded", timeout: 30000 });
    result.navStatus = response?.status() ?? null;
    result.mediaQueryMatches = await page.evaluate(() => matchMedia("(prefers-reduced-motion: reduce)").matches);
    if (!result.mediaQueryMatches) throw new Error("browser did not emulate prefers-reduced-motion: reduce");
    try {
      await page.locator('[data-qc-command-frame="prestige-v1"]').waitFor({ state: "visible", timeout: 15000 });
    } catch (error) {
      result.awakeningCount = await page.locator(".qc-sovereign-awakening").count();
      result.awakeningPhase = await page.locator(".qc-sovereign-awakening").getAttribute("data-qc-awakening-phase").catch(() => null);
      result.bodyTextSample = (await page.locator("body").innerText().catch(() => "")).slice(0, 1000);
      throw error;
    }
    result.awakeningPresent = await page.locator(".qc-sovereign-awakening").count();
    if (result.awakeningPresent !== 0) throw new Error("reduced-motion user remained trapped in cinematic awakening");
    const overflow = await page.evaluate(() => Math.max(0, document.documentElement.scrollWidth - document.documentElement.clientWidth));
    result.horizontalOverflowPx = overflow;
    result.pageErrors = pageErrors;
    if (overflow > 1) throw new Error(`reduced-motion horizontal overflow ${overflow}px`);
    if (pageErrors.length) throw new Error(`reduced-motion page errors: ${pageErrors.join(" | ")}`);
    await page.screenshot({ path: `${evidenceDir}/reduced-motion-command-field.png`, fullPage: true });
  } catch (error) {
    failures += 1;
    result.hardFailure = true;
    result.error = String(error);
    await page.screenshot({ path: `${evidenceDir}/reduced-motion-failure.png`, fullPage: true }).catch(() => {});
  }
  report.reducedMotion = result;
  console.log("QC_REDUCED_MOTION_RESULT " + JSON.stringify(result));
  await context.close();
}

await browser.close();
report.summary = { failures };
await fs.writeFile(`${evidenceDir}/report.json`, JSON.stringify(report, null, 2));
console.log("QC_IDENTITY_SUMMARY " + JSON.stringify(report.summary));
if (failures) process.exitCode = 1;
