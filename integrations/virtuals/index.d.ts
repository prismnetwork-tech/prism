import type { GameFunction, GameWorker } from "@virtuals-protocol/game";
import type { PrismToolset } from "@prismnetwork/agent-sdk/toolset";

export declare class PrismGamePlugin {
  constructor(options?: { toolset?: PrismToolset; id?: string });
  readonly id: string;
  readonly toolset: PrismToolset;
  getWorker(): GameWorker;
  readonly listGpusFunction: GameFunction<[]>;
  readonly walletFunction: GameFunction<[]>;
  readonly leaseAndRunFunction: GameFunction<never[]>;
  readonly runFunction: GameFunction<never[]>;
  readonly endLeaseFunction: GameFunction<never[]>;
}

export default PrismGamePlugin;
