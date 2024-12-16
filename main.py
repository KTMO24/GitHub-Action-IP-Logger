import express from 'express';
import session from 'express-session';
import fetch from 'node-fetch';
import dotenv from 'dotenv';

dotenv.config();

const {
  GITHUB_CLIENT_ID,
  GITHUB_CLIENT_SECRET,
  SESSION_SECRET,
  PORT
} = process.env;

if (!GITHUB_CLIENT_ID || !GITHUB_CLIENT_SECRET || !SESSION_SECRET) {
  console.error("Missing required environment variables.");
  process.exit(1);
}

const app = express();

// Middleware to parse JSON body for event logging endpoints
app.use(express.json());

// Session Middleware
app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false } // In production, set secure: true and use HTTPS
}));

// In-memory event storage (In production, use a database)
const events = [];

// Generate a random state to protect from CSRF attacks during OAuth
function generateState() {
  return Math.random().toString(36).substring(2, 15);
}

// ------ Routes ------

// Home Page
app.get('/', (req, res) => {
  if (req.session.user) {
    res.send(`
      <h1>Hello, ${req.session.user.login}!</h1>
      <p><img src="${req.session.user.avatar_url}" width="100" height="100"/></p>
      <p><a href="/logout">Logout</a></p>
      <p><a href="/events">View Logged Events</a></p>
      <p><a href="/new-event">Log a New Event</a></p>
    `);
  } else {
    res.send(`
      <h1>Welcome! Please log in with GitHub</h1>
      <p><a href="/auth/github">Login with GitHub</a></p>
      <p><a href="/events">View Logged Events (public)</a></p>
    `);
  }
});

// Step 1: Redirect user to GitHub for authorization
app.get('/auth/github', (req, res) => {
  const state = generateState();
  req.session.oauthState = state;

  const redirectUri = `https://github.com/login/oauth/authorize?client_id=${GITHUB_CLIENT_ID}&scope=user:email&state=${state}`;
  res.redirect(redirectUri);
});

// Step 2: GitHub redirects back to our callback with a temporary code
app.get('/auth/github/callback', async (req, res) => {
  const { code, state } = req.query;

  // Validate state
  if (!state || state !== req.session.oauthState) {
    return res.status(403).send('Invalid state parameter. Possible CSRF attack.');
  }

  // Exchange the code for an access token
  const tokenResponse = await fetch('https://github.com/login/oauth/access_token', {
    method: 'POST',
    headers: {
      'Accept': 'application/json',
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      client_id: GITHUB_CLIENT_ID,
      client_secret: GITHUB_CLIENT_SECRET,
      code: code,
      state: state
    })
  });

  const tokenData = await tokenResponse.json();

  if (!tokenData.access_token) {
    return res.status(401).send('Failed to get access token from GitHub');
  }

  // Use the access token to fetch user info
  const userResponse = await fetch('https://api.github.com/user', {
    headers: {
      'Authorization': `Bearer ${tokenData.access_token}`
    }
  });
  const userData = await userResponse.json();

  if (userData && userData.login) {
    // User is authenticated via GitHub. Store in session.
    req.session.user = {
      login: userData.login,
      id: userData.id,
      avatar_url: userData.avatar_url
    };

    // Redirect user to the protected area or home
    res.redirect('/');
  } else {
    res.status(500).send('Failed to retrieve user information from GitHub');
  }
});

// Logout endpoint
app.get('/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) return res.status(500).send('Could not log out.');
    res.redirect('/');
  });
});

// Events Listing (Public)
app.get('/events', (req, res) => {
  // Display events in a simple format
  const eventList = events.map(evt => {
    return `
      <div>
        <strong>Timestamp:</strong> ${evt.timestamp}<br/>
        <strong>Event:</strong> ${evt.type}<br/>
        <strong>User:</strong> ${evt.user ? evt.user : 'Not Logged In'}<br/>
        <strong>IP:</strong> ${evt.ip}<br/>
        <strong>Details:</strong> ${evt.details}<br/><hr/>
      </div>
    `;
  }).join('');
  res.send(`
    <h1>Logged Events</h1>
    ${eventList || '<p>No events logged yet.</p>'}
    <p><a href="/">Go Home</a></p>
  `);
});

// Page to log a new event (If logged in)
app.get('/new-event', (req, res) => {
  if (!req.session.user) {
    return res.status(401).send('<h1>Please <a href="/">login</a> first.</h1>');
  }
  // A simple form to submit a new event
  res.send(`
    <h1>Create a New Event</h1>
    <form action="/events" method="POST">
      <label>Event Type: <input name="type" value="repo_push"/></label><br/>
      <label>Details: <input name="details" value="Pushed changes to main branch"/></label><br/>
      <button type="submit">Log Event</button>
    </form>
    <p><a href="/">Go Home</a></p>
  `);
});

// POST route to log an event
app.post('/events', (req, res) => {
  const user = req.session.user ? req.session.user.login : null;
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress; // Basic IP extraction

  const { type, details } = req.body;

  // Validate inputs (basic)
  if (!type || !details) {
    return res.status(400).send('Missing event type or details');
  }

  const event = {
    timestamp: new Date().toISOString(),
    type: type,
    user: user,
    ip: ip,
    details: details
  };

  events.push(event);

  res.redirect('/events');
});

app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
