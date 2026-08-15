import { describe, expect, it } from "vitest";
import { STAGES, digestOf, normalise } from "./refraction";

describe("normalise", () => {
  it("accepts the ways a person actually types an answer", async () => {
    const forms = ["RTX 5880Ada", "rtx5880ada", "RTX-5880-Ada", "  rtx 5880 ada  "];
    const digests = await Promise.all(forms.map(digestOf));
    expect(new Set(digests).size).toBe(1);
    expect(digests[0]).toBe(STAGES[0].digest);
  });

  it("keeps meaning, drops decoration", () => {
    expect(normalise("Block #36,905,928")).toBe("block36905928");
    expect(normalise("300 seconds")).toBe("300seconds");
  });
});

describe("the stages", () => {
  // Each answer is checked against its digest, so a typo in the puzzle data
  // makes a correct answer unrecognisable and the bounty unwinnable.
  const answers = ["RTX 5880Ada", "36905928", "300", "15380189"];

  it("recognise their intended answers", async () => {
    for (const [index, stage] of STAGES.entries()) {
      expect(await digestOf(answers[index])).toBe(stage.digest);
    }
  });

  it("do not carry an answer in plain text", () => {
    const bundled = JSON.stringify(STAGES).toLowerCase();
    for (const answer of answers) {
      expect(bundled).not.toContain(normalise(answer));
    }
  });

  it("combine into the string the prize contract accepts", () => {
    // keccak256 of this is 0x27583600858ee9bb4a375be967567e0dd7ee3365f790d5ea540687dd80ab0162,
    // which is the answerHash the deployed contract was constructed with.
    expect(answers.map(normalise).join("-")).toBe("rtx5880ada-36905928-300-15380189");
  });

  it("are all present and distinct", () => {
    expect(STAGES).toHaveLength(4);
    expect(new Set(STAGES.map((stage) => stage.digest)).size).toBe(4);
    expect(STAGES.map((stage) => stage.index)).toEqual([1, 2, 3, 4]);
  });
});
