import { expect, Page } from "@playwright/test";

export const ROOT_USER = process.env.E2E_USER ?? "e2eadmin";
export const ROOT_PASSWORD = process.env.E2E_PASSWORD ?? "e2esecret123";

export async function login(page: Page, user = ROOT_USER, password = ROOT_PASSWORD) {
  await page.goto("/login");
  await page.getByTestId("access-key").fill(user);
  await page.getByTestId("secret-key").fill(password);
  await page.getByTestId("login").click();
  await expect(page.getByTestId("whoami")).toHaveText(user);
}

export const unique = (p: string) => `${p}-${Date.now().toString(36)}${Math.floor(Math.random() * 1000)}`;
