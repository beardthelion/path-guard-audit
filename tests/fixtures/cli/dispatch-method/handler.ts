import { readFileSync } from "fs";

export async function handle(args: any) {
  return readFileSync(args.path, "utf8");
}
