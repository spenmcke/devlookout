import { faultList } from "../../../packages/shared/src/faults";
import { config } from "./config";

const baseUrl = process.env.HIMALAYAS_API_URL ?? `http://localhost:${config.port}`;

async function main(): Promise<void> {
  for (const fault of faultList) {
    const response = await fetch(`${baseUrl}${fault.route}`, {
      method: "POST",
      headers: {
        "content-type": "application/json"
      },
      body: JSON.stringify({
        account_domain: fault.accountDomain,
        locale: fault.locale,
        region: fault.region
      })
    });

    const payload = await response.text();
    const expected = response.status >= 500;
    console.log(
      `${fault.key}: ${response.status} ${expected ? "captured" : "unexpected"} ${payload.slice(0, 180)}`
    );
  }
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
