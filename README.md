# Poznote — Unrestricted ZIP Attachment Import to Remote Code Execution

## Security research by DarkOcelot

This repository documents a security vulnerability affecting Poznote, a self-hosted note-taking and knowledge-management application.

The vulnerability, tracked as **GHSA-3v39-q26w-c3h7**, combines insufficient ZIP attachment validation with an Nginx configuration issue, potentially allowing authenticated users to achieve Remote Code Execution (RCE).

## Vulnerability Information
|Property|	Details|
|--|--|
|Application|Poznote|
|Vulnerability|	Unrestricted File Upload|
|Impact	|Remote Code Execution|
|Severity|	Critical|
|CVSS	|9.9|
|Affected versions|	Earlier than 6.21.1|
|Fixed version|	6.21.1|
|Authentication|	Required|
|Advisory|	GHSA-3v39-q26w-c3h7|
|Weaknesses|	CWE-434, CWE-94|

## Overview

The vulnerability originates in the attachment ZIP import functionality.

The importAttachmentsZip() function in restore_import.php validates the uploaded archive format but does not adequately validate the individual files contained within it.

As a result, potentially executable files can be extracted into the application's attachment directory.

The impact is amplified by the bundled Nginx configuration, which allows PHP files in the attachment directory to reach PHP-FPM.

The combination of these issues can result in remote code execution under the privileges of the PHP-FPM process.

## Attack Flow
- An authenticated user accesses the attachment import functionality.
- A ZIP archive containing an unsupported file type is imported.
- The application extracts the archive entries into the attachments directory.
- The uploaded file becomes accessible through the web server.
- The Nginx PHP handler forwards the request to PHP-FPM.
- PHP-FPM processes the uploaded file.

## Testing requirements:

- An isolated Poznote installation (6.21.0 or earlier)
- A test account with access to attachment imports.

## Impact

Successful exploitation can allow an authenticated user to execute arbitrary PHP code with the privileges of the PHP-FPM worker process.

Website: https://darkocelot.com

GitHub: https://github.com/Dark-Ocelot
