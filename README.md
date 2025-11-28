# IT-360-Group-Project-Sect-1
Group project Video Link - https://www.youtube.com/watch?v=hCE_tduFuO0
This project's goal is to monitor and detect spam or phishing emails. An automated email forensics tool is used to analyze the email information by looking at the headers, body, and attachments. Using Microsoft Graph API grab message data, parse headers, and evaluate based on security indicators.

Using the generated one-time code to sign in to the application, a function grabs your latest email, and looks at different headers like ID, who it is from, the time that it was recieved, whether it has attachments or not, and several other headers. Grabbed data is then converted from HTML to readable text with BeautifulSoup, and the text is analyzed and compared with wordlists and different expressions/funtions.

To begin, run the program, it will return with a link and a one-time code for sign in. You will then be able to view the analysis.
