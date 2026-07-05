# Title: IDOR in GraphQL — Access Other Users' Billing Invoices - $5,000

- **Platform**: HackerOne
- **Program**: Shopify Bug Bounty Program
- **Severity**: High
- **Date**: 2024-02-08
- **Researcher**: blaklis
- **Bounty**: $5,000

## Summary
An insecure direct object reference vulnerability was discovered in Shopify's GraphQL API. The `BillingDocumentDownload` and `BillDetails` GraphQL queries allowed staff users to access billing invoices of any Shopify shop by simply tampering with BillingInvoice IDs.

## Technical Details
Shopify's staff interface uses GraphQL for many operations, including billing management. The `BillingDocumentDownload` and `BillDetails` queries accepted a BillingInvoice ID as a parameter to retrieve invoice documents and details.

The vulnerability was that these queries did not verify whether the authenticated staff user had permission to access the specified shop's billing data. Staff users in one organization could access billing invoices for shops in completely different organizations by changing the invoice ID.

This was discovered by analyzing the GraphQL schema (introspection was likely enabled) and finding these undocumented or internal queries. The billing invoice IDs were sequential or predictable, making enumeration possible.

## Steps to Reproduce
1. Log into Shopify as a staff user
2. Use a GraphQL client (graphql-client, Altair, etc.)
3. Send a query for `BillingDocumentDownload` with a known invoice ID
4. Change the invoice ID to another shop's invoice
5. The response returns the other shop's billing document
6. Repeat for `BillDetails` query

## Proof of Concept
```graphql
query {
  BillingDocumentDownload(billingInvoiceId: "gid://shopify/BillingInvoice/987654") {
    url
    filename
    contentType
  }
}
```

Changing the `billingInvoiceId` to values from other shops returns their invoice documents without authorization.

## Impact
- Access to billing invoices and financial data of other Shopify shops
- Disclosure of revenue, transaction details, and merchant information
- Financial intelligence gathering on competitors
- Privacy violation for shop owners
- Potential fraud using exposed financial data

## Remediation
Shopify fixed the vulnerability by implementing proper authorization checks in the GraphQL resolvers for `BillingDocumentDownload` and `BillDetails`. The queries now verify that the authenticated staff user has the correct permissions for the specific shop before returning billing data.

## References
- https://hackerone.com/reports/2207248
- https://github.com/ReddCrow12/documents-BBP
