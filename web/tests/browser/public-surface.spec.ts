import { expect, test } from "@playwright/test";

test("public build shows research without owner operations", async ({ page }) => {
  test.skip(process.env.VITE_LEGALBOT_OWNER_UI === "1", "owner build is tested separately");

  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Legal research you can inspect." })).toBeVisible();
  await expect(page.getByRole("link", { name: "Operations" })).toHaveCount(0);
  await expect(page.getByLabel("Open operations dashboard")).toHaveCount(0);
  await expect(page.getByLabel("Owner development chat")).toHaveCount(0);

  await page.goto("/admin");
  await expect(page).toHaveURL("http://127.0.0.1:8777/");
  await expect(page.getByRole("heading", { name: "Legal research you can inspect." })).toBeVisible();
});
