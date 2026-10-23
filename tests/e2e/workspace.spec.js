import { test, expect } from "@playwright/test";

async function open(page, view = "overview") {
  await page.goto(`/#${view}`);
  await expect(page.locator(".page-footer")).toBeVisible();
}
async function navigate(page, label, title = label) {
  await page
    .locator("nav")
    .getByRole("button", { name: new RegExp(`^${label}`) })
    .click();
  await expect(page.locator(".page-heading h1")).toContainText(title);
}
async function role(page, name) {
  await navigate(page, "Permissions");
  const card = page.getByRole("button", {
    name: new RegExp(`${name}.*Try ${name.toLowerCase()} role`, "i"),
  });
  await card.click();
  await expect(page.locator(".page-footer")).toContainText(
    name === "Administrator" ? "Admin access" : `${name} access`,
  );
}

test("all thirteen workspace views load and event search filters actual rows", async ({
  page,
}) => {
  const errors = [];
  page.on("pageerror", (error) => errors.push(error.message));
  await open(page);
  await expect(
    page.getByRole("heading", { name: /Stay a step ahead/ }),
  ).toBeVisible();
  const views = [
    ["Log monitoring", "Log monitoring"],
    ["Threat intelligence", "Threat intelligence"],
    ["Threat hunting", "Threat hunting"],
    ["Security scanner", "Security scanner"],
    ["VPN history", "VPN history"],
    ["Firewall", "Firewall"],
    ["TCP connections", "TCP connections"],
    ["Malware analysis", "Malware analysis"],
    ["Packet sniffer", "Packet sniffer"],
    ["Investigations", "Investigations"],
    ["Permissions", "Permissions"],
    ["Security academy", "Security academy"],
    ["Overview", "Security overview"],
  ];
  for (const [label, title] of views) await navigate(page, label, title);
  await navigate(page, "Log monitoring");
  await page.getByRole("textbox", { name: "Search logs" }).fill("powershell");
  await expect(page.locator("tbody > tr")).toHaveCount(1);
  await expect(page.locator("tbody")).toContainText("Suspicious process");
  await page
    .getByRole("combobox", { name: "Filter log severity" })
    .selectOption("low");
  await expect(
    page.getByRole("heading", { name: "No matching events" }),
  ).toBeVisible();
  expect(errors).toEqual([]);
});

test("inventory, VPN, TCP, file triage, hunt and packet replay return useful results", async ({
  page,
}) => {
  await open(page, "scanner");
  await page.getByRole("button", { name: "Run assessment" }).click();
  await expect(
    page.getByText("Assessment complete", { exact: true }),
  ).toBeVisible();
  await expect(page.locator(".analysis-result tbody > tr")).not.toHaveCount(0);

  await navigate(page, "VPN history");
  await page.getByRole("button", { name: "Analyze sample history" }).click();
  await expect(page.locator(".analysis-finding")).not.toHaveCount(0);
  await expect(page.locator(".analysis-findings")).toContainText(
    /impossible.travel/i,
  );

  await navigate(page, "TCP connections");
  await page.getByRole("button", { name: "Analyze TCP flows" }).click();
  await expect(
    page.getByText("4 half-open connections need attention", { exact: true }),
  ).toBeVisible();
  await page
    .getByText("Analyze your own connection data", { exact: true })
    .click();
  await page.getByRole("textbox", { name: "Connection records (JSON)" }).fill(
    JSON.stringify([
      {
        source: "10.0.0.1",
        destination: "10.0.0.2",
        port: 443,
        state: "SYN_SENT",
        ageSeconds: 1,
      },
      {
        source: "10.0.0.3",
        destination: "10.0.0.2",
        port: 443,
        state: "SYN_SENT",
        ageSeconds: 45,
      },
    ]),
  );
  await page.getByRole("button", { name: "Analyze TCP flows" }).click();
  await expect(
    page.getByText("1 half-open connections need attention", { exact: true }),
  ).toBeVisible();

  await navigate(page, "Malware analysis");
  await page.getByRole("button", { name: "Use a harmless sample" }).click();
  await page.getByRole("button", { name: "Analyze file", exact: true }).click();
  await expect(page.locator(".analysis-hash")).toHaveText(/^[a-f0-9]{64}$/);
  await expect(
    page.getByText("Indicators found", { exact: true }),
  ).toBeVisible();

  await navigate(page, "Threat hunting");
  await page.getByRole("textbox", { name: "HUNT QUERY" }).fill("powershell");
  await page.getByRole("button", { name: "Run hunt" }).click();
  await expect(
    page.getByText("1 log matches · 0 intelligence matches", { exact: true }),
  ).toBeVisible();

  await navigate(page, "Packet sniffer");
  const before = await page.locator("tbody > tr").count();
  await page.getByRole("button", { name: "Start demo capture" }).click();
  await expect
    .poll(() => page.locator("tbody > tr").count())
    .toBeGreaterThan(before);
  await page.getByRole("button", { name: "Pause capture" }).click();
  await page
    .getByRole("combobox", { name: "Filter packet protocol" })
    .selectOption("TCP");
  await expect(page.locator("tbody tr").first()).toContainText("TCP");
  await page.getByRole("button", { name: "Clear buffer" }).click();
  await expect(
    page.getByRole("heading", { name: "The packet buffer is empty." }),
  ).toBeVisible();
});

test("five-question quiz grades selected answers and resets", async ({
  page,
}) => {
  await open(page, "academy");
  await expect(page.locator(".sec-question-progress > button")).toHaveCount(5);
  const answers = [
    /Isolate it and preserve evidence/,
    /SYN → SYN-ACK → ACK/,
    /Potential account compromise or VPN routing/,
    /Grant only the permissions needed for a role/,
    /Whether it matches a known file or indicator/,
  ];
  for (const [index, answer] of answers.entries()) {
    await page.getByRole("radio", { name: answer }).check();
    if (index < 4)
      await page.getByRole("button", { name: "Next question" }).click();
  }
  await page.getByRole("button", { name: "Check answers" }).click();
  await expect(
    page.getByRole("heading", { name: "Your instincts are on point." }),
  ).toBeVisible();
  await expect(page.locator(".sec-review-icon.correct")).toHaveCount(5);
  await expect(page.locator(".sec-score-ring strong")).toHaveText("5/5");
  await page.getByRole("button", { name: "Take it again" }).click();
  await expect(
    page.getByText("0 of 5 answered", { exact: true }),
  ).toBeVisible();
});

test("viewer is denied mutation while administrator can manage rules and contain demo assets", async ({
  page,
}) => {
  await open(page);
  await role(page, "Viewer");
  await navigate(page, "Security scanner");
  await expect(
    page.getByRole("button", { name: "Run assessment" }),
  ).toBeDisabled();
  const forbidden = await page.evaluate(async () => {
    const result = await fetch("/api/firewall", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${sessionStorage.getItem("archer-token")}`,
      },
      body: JSON.stringify({ name: "Must not be created" }),
    });
    return result.status;
  });
  expect(forbidden).toBe(403);
  await navigate(page, "Firewall");
  await expect(
    page.getByRole("button", { name: "Create rule", exact: true }),
  ).toBeDisabled();
  await role(page, "Administrator");
  await navigate(page, "Firewall");
  await page.getByRole("button", { name: "Create rule", exact: true }).click();
  await page
    .getByRole("textbox", { name: "Rule name", exact: true })
    .fill("E2E deny policy");
  await page
    .locator("form")
    .getByRole("button", { name: "Create rule", exact: true })
    .click();
  await expect(
    page.getByText("E2E deny policy", { exact: true }),
  ).toBeVisible();
  await page
    .getByRole("button", { name: "Remove E2E deny policy", exact: true })
    .click();
  await expect(page.getByText("E2E deny policy", { exact: true })).toHaveCount(
    0,
  );
  await navigate(page, "Overview", "Security overview");
  await page.getByRole("button", { name: /workstation-047/ }).click();
  await page
    .getByRole("dialog")
    .getByRole("button", { name: "Investigate", exact: true })
    .click();
  await navigate(page, "Investigations");
  await expect(page.locator(".sec-case")).not.toHaveCount(0);
  await page.locator(".sec-case-trigger").first().click();
  await expect(
    page.getByText("INVESTIGATION FINDINGS", { exact: true }),
  ).toBeVisible();
  await navigate(page, "Overview", "Security overview");
  await page.getByRole("button", { name: /workstation-047/ }).click();
  await page
    .getByRole("dialog")
    .getByRole("button", { name: "Isolate", exact: true })
    .click();
  await expect(
    page.getByRole("button", { name: /workstation-047/ }),
  ).toContainText("isolated");
  await page.getByRole("button", { name: /web-server-02/ }).click();
  await page
    .getByRole("dialog")
    .getByRole("button", { name: "Block", exact: true })
    .click();
  await expect(
    page.getByRole("button", { name: /web-server-02/ }),
  ).toContainText("blocked");
});

test("mobile navigation and workspace stay within the viewport", async ({
  page,
}) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await open(page);
  await expect(
    page.getByRole("button", { name: "Open navigation" }),
  ).toBeVisible();
  await page.getByRole("button", { name: "Open navigation" }).click();
  await navigate(page, "VPN history");
  const dimensions = await page.evaluate(() => ({
    scroll: document.documentElement.scrollWidth,
    viewport: innerWidth,
  }));
  expect(dimensions.scroll).toBeLessThanOrEqual(dimensions.viewport);
  await page.getByRole("button", { name: "Open navigation" }).click();
  await navigate(page, "Overview", "Security overview");
  await page.screenshot({ path: "/tmp/archer-mobile.png", fullPage: true });
});
