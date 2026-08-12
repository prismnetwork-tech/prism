import type { Metadata } from "next";
import { InformationPage } from "@/components/information-page";
import { FaqStructuredData } from "@/components/structured-data";
import { faq } from "@/lib/faq";

export const metadata: Metadata = {
  title: "Questions",
  description:
    "What GPU compute costs on Prism, which payment methods are accepted, what a host can see, how the vault keeps data private, and what providers earn.",
  alternates: { canonical: "/faq" },
};

export default function FaqPage() {
  return (
    <>
      <FaqStructuredData />
      <InformationPage
        eyebrow="Product / Questions"
        title="Questions people ask before renting."
        description="Short answers about cost, payment, what a host can see, and what happens when something fails. Where an answer has a limit, the limit is stated."
      >
        <div className="faq-list">
          {faq.map((entry) => (
            <div className="faq-item" key={entry.question}>
              <h2>{entry.question}</h2>
              <p>{entry.answer}</p>
            </div>
          ))}
        </div>
      </InformationPage>
    </>
  );
}
