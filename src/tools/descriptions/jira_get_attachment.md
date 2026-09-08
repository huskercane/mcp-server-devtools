Download a Jira image attachment and return an MCP image block the assistant can view. Preserves the original bytes; no text or JSON conversion. Supports PNG, JPEG, GIF, and WebP up to 5 MiB.

First use jira_get with path `/rest/api/3/issue/{issueKey}`, queryParams `{"fields":"attachment"}`, and jq `fields.attachment[*].{id:id,filename:filename,mimeType:mimeType,size:size}`. Pass the selected numeric ID as attachmentId.

Use this tool for screenshot contents instead of jira_get. Media UUIDs and blob URLs from rendered comments are not Jira attachment IDs. Non-image attachments return an error.
