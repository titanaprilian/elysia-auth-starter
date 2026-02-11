import type { NodePlopAPI } from "plop";
import path from "node:path";

export default function (plop: NodePlopAPI) {
  const rootDir = process.cwd();
  const templatesDir = path.join(rootDir, "src/scripts/templates");

  plop.setHelper("lowercase", (text: string) => text.toLowerCase());
  plop.setHelper(
    "capitalize",
    (text: string) => text.charAt(0).toUpperCase() + text.slice(1),
  );

  plop.setGenerator("module", {
    description: "Generate Elysia module (CRUD)",
    prompts: [
      {
        type: "input",
        name: "name",
        message: "Module name (singular, e.g. user)",
        validate: (value: string) => (value ? true : "Module name is required"),
      },
    ],
    actions: [
      {
        type: "add",
        path: path.join(rootDir, "src/modules/{{lowercase name}}/index.ts"),
        templateFile: path.join(templatesDir, "index.hbs"),
      },
      {
        type: "add",
        path: path.join(rootDir, "src/modules/{{lowercase name}}/model.ts"),
        templateFile: path.join(templatesDir, "model.hbs"),
      },
      {
        type: "add",
        path: path.join(rootDir, "src/modules/{{lowercase name}}/schema.ts"),
        templateFile: path.join(templatesDir, "schema.hbs"),
      },
      {
        type: "add",
        path: path.join(rootDir, "src/modules/{{lowercase name}}/params.ts"),
        templateFile: path.join(templatesDir, "params.hbs"),
      },
      {
        type: "add",
        path: path.join(rootDir, "src/modules/{{lowercase name}}/service.ts"),
        templateFile: path.join(templatesDir, "service.hbs"),
      },
    ],
  });
}
