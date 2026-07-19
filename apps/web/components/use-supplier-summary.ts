"use client";

import { useQuery } from "@tanstack/react-query";
import { usePrismAuth } from "@/components/providers";
import { fetchSupplierSummary } from "@/lib/supplier";

export function useSupplierSummary() {
  const auth = usePrismAuth();
  const query = useQuery({
    queryKey: ["supplier-summary", auth.userId],
    queryFn: ({ signal }) => fetchSupplierSummary(signal),
    enabled: auth.authenticated,
    staleTime: 15_000,
  });
  return { auth, ...query };
}
