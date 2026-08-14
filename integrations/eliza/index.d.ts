interface PrismAction {
  name: string;
  similes: string[];
  description: string;
  validate: (runtime: unknown, message: unknown) => Promise<boolean>;
  handler: (
    runtime: unknown,
    message: unknown,
    state?: unknown,
    options?: unknown,
    callback?: (content: { text: string; actions: string[] }) => Promise<unknown>,
  ) => Promise<{ success: boolean; text: string }>;
  examples: Array<Array<{ name: string; content: { text: string; actions?: string[] } }>>;
}

interface PrismProvider {
  name: string;
  description: string;
  dynamic: boolean;
  get: (runtime?: unknown) => Promise<{ text: string }>;
}

export declare const prismPlugin: {
  name: string;
  description: string;
  actions: PrismAction[];
  providers: PrismProvider[];
};

export default prismPlugin;
