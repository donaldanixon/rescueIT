const express = require('express');
const cors = require('cors');
const sql = require('mssql');
const bcrypt = require('bcrypt');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const jwtSecret = process.env.RESCUEITJWTsecret;
const rescueITDBpassword = process.env.RESCUEITDBpassword;

// SQL Connection
const config = {
    user: 'masteruser',
    password: rescueITDBpassword,
    server: 'rescueitdb.database.windows.net',
    database: 'rescueitdb',
    port: 1433,
    options: {
      encrypt: true, 
      trustServerCertificate: false
    },
    pool: {
      max: 3, 
      min: 0, 
      idleTimeoutMillis: 30000
    }
  };

// Create a connection pool
const poolPromise = new sql.ConnectionPool(config)
.connect()
.then(pool => {
    console.log('Connected to SQL Server');
    return pool;
})
.catch(err => {
    console.error('Database Connection Failed:', err);
    process.exit(1);
});

// Setup Express App
const app = express();
app.use(cors());
app.use(express.json());

// Middleware to attach the pool to the request
app.use(async (req, res, next) => {
try {
    req.pool = await poolPromise;
    next();
} catch (err) {
    next(err);
}
});

// Handle preflight requests
app.use((req, res, next) => {
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE'); 
    res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization'); 
  
    if (req.method === 'OPTIONS') {
      res.sendStatus(200); // Respond to preflight requests
    } else {
      next();
    }
});

// Rate limiting middleware
const limiter = rateLimit({
windowMs: 15 * 60 * 1000, // 15 minutes
max: 100 // Limit each IP to 100 requests per windowMs
});
app.use(limiter);

const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
  
    if (!token) return res.status(401).send("Missing header");
  
    jwt.verify(token, jwtSecret, (err, user) => {
      if (err) return res.status(401).send("Invalid token");
      req.user = user;
      next();
    });
};


const corsOptions = {
    methods: ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  };
app.use(cors(corsOptions));
  
app.use(express.json());
app.listen(8080, () => {
    console.log('Listening on port 8080')
    }
);

// Helper functions
function invalidQuery(query) {
    const sqlInjectionPattern = /;\s*\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|TRUNCATE|REPLACE|GRANT|REVOKE|UNION|EXEC|EXECUTE|DECLARE)\b|--|\/\*|\*\/|;/i;
    return sqlInjectionPattern.test(query);
}


// Routes
// - Front page
app.get('/', (req, res) => {
    res.send('Welcome to the RescueIt API! We have cookies and donuts');
    }
);

// - Login
app.post('/users/login', async (req, res) => {
    let { username, password } = req.body;
    if (!username) {
        return res.status(400).send("Username cannot be empty");
    }
    if (!password) {
        return res.status(400).send("Password cannot be empty");
    }
    if (invalidQuery(username) || invalidQuery(password)) {
        return res.status(400).send('Invalid query');
    }
    console.log('Logging in ' + username);
    
    try {
        const pool = await req.pool;
        const result = await pool.request()
            .input('username', sql.VarChar, username)
            .query('SELECT * FROM users WHERE username = @username');

        const users = result.recordset;

        if (users.length === 0) {
            return res.status(401).send('User not found');
        }

        const user = users[0];
        
        bcrypt.compare(password, user.userpswd, (err, isMatch) => {
            if (err) {
                return res.status(400).send(err);
            }
            if (isMatch) {
                console.log('Login successful');
                const token = jwt.sign(
                    { userId: user.userID, role: user.userrole, userName: user.username },
                    jwtSecret,
                    { expiresIn: '24h' }
                );
                return res.json({ 
                    token: token,
                    userId: user.userID, 
                    role: user.userrole, 
                    userName: user.username
                });
            } else {
                console.log('Incorrect password');
                return res.status(401).send('Incorrect password');
            }
        });
    } catch (err) {
        console.log(err);
        return res.status(500).send('Internal Server Error');
    }
});


// - Register
app.post('/users/register', async (req, res) => {
    console.log('Registering user...');
    let { username, password, userrole } = req.body;
    
    // Ensure no empty fields
    if (!username) {
        return res.status(400).send("Username cannot be empty");
    }
    if (!password) {
        return res.status(400).send("Password cannot be empty");
    }
    if (!userrole) {
        return res.status(400).send("User role cannot be empty");
    }

    // Validate query
    if (invalidQuery(username) || invalidQuery(password) || invalidQuery(userrole)) {
        return res.status(400).send('Invalid query');
    }

    try {
        const pool = await req.pool;

        // Validate username to check for uniqueness
        const checkResult = await pool.request()
            .input('username', sql.VarChar, username)
            .query('SELECT * FROM users WHERE username = @username');

        if (checkResult.recordset.length > 0) {
            return res.status(401).send('Username already exists');
        }

        // Encrypt password and insert into database
        bcrypt.hash(password, 10, async (err, hash) => {
            if (err) {
                return res.status(400).send(err);
            }

            try {
                const insertResult = await pool.request()
                    .input('username', sql.VarChar, username)
                    .input('userpswd', sql.VarChar, hash)
                    .input('userrole', sql.VarChar, userrole)
                    .query('INSERT INTO users (username, userpswd, userrole) VALUES (@username, @userpswd, @userrole)');

                return res.json({
                    user: username
                });
            } catch (insertErr) {
                console.log(insertErr);
                return res.status(400).send(insertErr);
            }
        });
    } catch (err) {
        console.log(err);
        return res.status(500).send('Internal Server Error');
    }
});


// - List users
app.get('/users', authenticateToken, async (req, res) => {
    console.log('Fetching users...');
    try {
        const pool = await req.pool;
        const result = await pool.request().query('SELECT * FROM users;');
        
        return res.json(result.recordset);
    } catch (err) {
        console.log(err);
        return res.status(400).send(err);
    }
});


// - Update username
app.patch('/users/updateusername', authenticateToken, async (req, res) => {
    console.log('Updating username...');
    let { username, newusername } = req.body;
    
    if (!username) {
        return res.status(400).send("Username cannot be empty");
    }
    if (!newusername) {
        return res.status(400).send("New Username cannot be empty");
    }

    // Validate query
    if (invalidQuery(username) || invalidQuery(newusername)) {
        return res.status(400).send('Invalid query');
    }

    try {
        const pool = await req.pool;
        const result = await pool.request()
            .input('username', sql.VarChar, username)
            .input('newusername', sql.VarChar, newusername)
            .query('UPDATE users SET username = @newusername WHERE username = @username');

        return res.json({
            updated: true
        });
    } 
    catch (err) {
        console.log(err);
        return res.status(400).send(err);
    }
});

// - Update password
app.patch('/users/updatepassword', authenticateToken, async (req, res) => {
    console.log('Updating password...');
    let { username, oldpassword, newpassword } = req.body;
    
    if (!username) {
        return res.status(400).send("Username cannot be empty");
    }
    if (!oldpassword) {
        return res.status(400).send("Old Password cannot be empty");
    }
    if (!newpassword) {
        return res.status(400).send("New Password cannot be empty");
    }

    // Validate query
    if (invalidQuery(username) || invalidQuery(oldpassword) || invalidQuery(newpassword)) {
        return res.status(400).send('Invalid query');
    }

    try {
        const pool = await req.pool;
        
        // Check if the user exists
        const result = await pool.request()
            .input('username', sql.VarChar, username)
            .query('SELECT * FROM users WHERE username = @username');

        const users = result.recordset;

        if (users.length === 0) {
            return res.status(401).send('User not found');
        }

        const user = users[0];

        // Compare the old password with the stored hashed password
        bcrypt.compare(oldpassword, user.userpswd, (err, isMatch) => {
            if (err) {
                return res.status(400).send(err);
            }
            if (isMatch) {
                console.log('Old password matches, updating password...');
                
                // Hash the new password
                bcrypt.hash(newpassword, 10, async (err, hash) => {
                    if (err) {
                        return res.status(400).send(err);
                    }
                    
                    try {
                        // Update the user's password in the database
                        await pool.request()
                            .input('username', sql.VarChar, username)
                            .input('userpswd', sql.VarChar, hash)
                            .query('UPDATE users SET userpswd = @userpswd WHERE username = @username');

                        return res.json({
                            user: username
                        });
                    } catch (updateErr) {
                        console.log(updateErr);
                        return res.status(400).send(updateErr);
                    }
                });
            } else {
                console.log('Incorrect password');
                return res.status(401).send('Incorrect password');
            }
        });
    } catch (err) {
        console.log(err);
        return res.status(500).send('Internal Server Error');
    }
});


// - Match fosterer from userID
app.post('/users/fosterer', authenticateToken, async (req, res) => {
    console.log('Fetching fosterer...');
    let { userID } = req.body;
    
    if (!userID) {
        return res.status(400).send("User ID cannot be empty");
    }
    if (typeof userID !== 'number') {
        return res.status(400).send("Invalid User ID");
    }

    try {
        const pool = await req.pool;

        // Fetch fosterer details
        const result = await pool.request()
            .input('userID', sql.Int, userID)
            .query('SELECT * FROM fosterers WHERE userID = @userID');

        const fosterers = result.recordset;

        if (fosterers.length === 0) {
            return res.status(404).send('Fosterer not found');
        }

        const fosterer = fosterers[0];

        return res.json({ 
            fostererID: fosterer.fostererID,
            bottleFeeder: fosterer.bottleFeeders
        });

    } catch (err) {
        console.log(err);
        return res.status(400).send(err);
    }
});


// - List all animals
app.get('/animals', authenticateToken, async (req, res) => {
    console.log('Fetching animals...');
    try {
        const pool = await req.pool;
        const result = await pool.request()
            .query('SELECT * FROM animals ORDER BY animalID DESC;');
        
        return res.json(result.recordset);
    } catch (err) {
        console.log(err);
        return res.status(400).send(err);
    }
});


// - Add animal
app.post('/animals/add', authenticateToken, async (req, res) => {
    console.log('Adding animal...');
    console.log(req.body);
    let { animalName, animalDOB, animalMicrochipNum, species, breed, secondaryBreed, gender, colour, secondaryColour, litterID, photoFileName, fostererID, surrenderedByID, desexed, awaitingDesex, inShelter, inFoster, awaitingFoster, underVetCare, deceased, deceasedDate, deceasedReason, incomingDate } = req.body;
    
    // Ensure required fields are provided
    if (!animalName) {
        return res.status(400).send("Animal name cannot be empty");
    }
    if (!species) {
        return res.status(400).send("Species cannot be empty");
    }

    // Validate query
    if (invalidQuery(animalName) || invalidQuery(animalMicrochipNum) || invalidQuery(species) || invalidQuery(breed) || invalidQuery(secondaryBreed) || invalidQuery(gender) || invalidQuery(colour) || invalidQuery(photoFileName)) {
        return res.status(400).send('Invalid query');
    }

    try {
        const pool = await req.pool;

        // Insert into database
        const result = await pool.request()
            .input('animalName', sql.VarChar, animalName)
            .input('animalDOB', sql.Date, animalDOB)
            .input('animalMicrochipNum', sql.VarChar, animalMicrochipNum)
            .input('species', sql.VarChar, species)
            .input('breed', sql.VarChar, breed)
            .input('secondaryBreed', sql.VarChar, secondaryBreed)
            .input('gender', sql.VarChar, gender)
            .input('colour', sql.VarChar, colour)
            .input('secondaryColour', sql.VarChar, secondaryColour)
            .input('litterID', sql.Int, litterID)
            .input('photoFileName', sql.VarChar, photoFileName)
            .input('fostererID', sql.Int, fostererID)
            .input('surrenderedByID', sql.Int, surrenderedByID)
            .input('desexed', sql.Bit, desexed)
            .input('awaitingDesex', sql.Bit, awaitingDesex)
            .input('inShelter', sql.Bit, inShelter)
            .input('inFoster', sql.Bit, inFoster)
            .input('awaitingFoster', sql.Bit, awaitingFoster)
            .input('underVetCare', sql.Bit, underVetCare)
            .input('deceased', sql.Bit, deceased)
            .input('deceasedDate', sql.Date, deceasedDate)
            .input('deceasedReason', sql.VarChar, deceasedReason)
            .input('incomingDate', sql.Date, incomingDate)
            .query(`INSERT INTO animals 
                    (animalName, animalDOB, animalMicrochipNum, species, breed, secondaryBreed, gender, colour, secondaryColour, litterID, photoFileName, fostererID, surrenderedByID, desexed, awaitingDesex, inShelter, inFoster, awaitingFoster, underVetCare, deceased, deceasedDate, deceasedReason, incomingDate) 
                    VALUES 
                    (@animalName, @animalDOB, @animalMicrochipNum, @species, @breed, @secondaryBreed, @gender, @colour, @secondaryColour, @litterID, @photoFileName, @fostererID, @surrenderedByID, @desexed, @awaitingDesex, @inShelter, @inFoster, @awaitingFoster, @underVetCare, @deceased, @deceasedDate, @deceasedReason, @incomingDate)`);
        
        return res.json({ created: true });
    } catch (err) {
        console.log(err);
        return res.status(400).send(err);
    }
});


// - Find animal
app.post('/animals/animal', authenticateToken, async (req, res) => {
    console.log('Fetching animal...');
    let { searchTerm, searchType } = req.body;

    if (!searchTerm) {
        return res.status(400).send("Search term cannot be empty");
    }

    if (!searchType) {
        return res.status(400).send("Search type cannot be empty");
    }

    // Validate query
    if (invalidQuery(searchTerm) || invalidQuery(searchType)) {
        return res.status(400).send('Invalid query');
    }

    let searchQuery = "";

    try {
        const pool = await req.pool;

        if (searchType === "Animal") {
            if (!isNaN(searchTerm)) {
                searchQuery = 'SELECT * FROM animals WHERE animalID = @searchTerm ORDER BY animalID DESC;';
            } else {
                searchQuery = 'SELECT * FROM animals WHERE animalName LIKE @searchTerm ORDER BY animalID DESC;';
                searchTerm = '%' + searchTerm + '%';
            }
        } else if (searchType === "Litter") {
            if (!isNaN(searchTerm)) {
                searchQuery = 'SELECT * FROM animals WHERE litterID = @searchTerm ORDER BY animalID DESC;';
            } else {
                searchQuery = 'SELECT * FROM animals WHERE litterID IN (SELECT litterID FROM litters WHERE litterName LIKE @searchTerm) ORDER BY animalID DESC;';
                searchTerm = '%' + searchTerm + '%';
            }
        } else if (searchType === "Fosterer") {
            if (!isNaN(searchTerm)) {
                searchQuery = 'SELECT * FROM animals WHERE fostererID = @searchTerm ORDER BY animalID DESC;';
            } else {
                searchQuery = 'SELECT * FROM animals WHERE fostererID IN (SELECT fostererID FROM fosterers WHERE fostererName LIKE @searchTerm) ORDER BY animalID DESC;';
                searchTerm = '%' + searchTerm + '%';
            }
        }

        const result = await pool.request()
            .input('searchTerm', sql.VarChar, searchTerm)
            .query(searchQuery);

        return res.json(result.recordset);

    } catch (err) {
        console.log(err);
        return res.status(400).send(err);
    }
});


// - Fetch animal by ID
app.get('/animals/animalbyid', authenticateToken, async (req, res) => {
    console.log('Fetching animal by ID...');
    let { animalID } = req.query;

    if (!animalID) {
        return res.status(400).send("Animal ID cannot be empty");
    }
    
    if (isNaN(animalID)) {
        return res.status(400).send('Not a valid animal ID');
    }

    try {
        const pool = await req.pool;

        const result = await pool.request()
            .input('animalID', sql.Int, animalID)
            .query('SELECT * FROM animals WHERE animalID = @animalID ORDER BY animalID DESC;');

        return res.json(result.recordset);

    } catch (err) {
        console.log(err);
        return res.status(400).send(err);
    }
});


// Find animals belonging to a fosterer
app.post('/animals/fosterer', authenticateToken, async (req, res) => {
    console.log('Fetching animals belonging to a fosterer...');
    let { fostererID } = req.body;

    if (!fostererID) {
        return res.status(400).send("Fosterer ID cannot be empty");
    }

    if (isNaN(fostererID)) {
        return res.status(400).send('Not a valid fosterer ID');
    }

    try {
        const pool = await req.pool;

        const result = await pool.request()
            .input('fostererID', sql.Int, fostererID)
            .query('SELECT * FROM animals WHERE fostererID = @fostererID ORDER BY animalID DESC;');

        return res.json(result.recordset);

    } catch (err) {
        console.log(err);
        return res.status(400).send(err);
    }
});


app.patch('/animals/update', authenticateToken, async (req, res) => {
    console.log('Updating animal...')
    let { animalID, animalName, animalDOB, animalMicrochipNum, species, breed, secondaryBreed, gender, colour, secondaryColour, litterID, photoFileName, fostererID, surrenderedByID, desexed, awaitingDesex, inShelter, awaitingFoster, inFoster, underVetCare, deceased, deceasedDate, deceasedReason, incomingDate } = req.body; 

    if (!animalID) {
        return res.status(400).send("Animal ID cannot be empty")
    }

    // Validate query
    if (invalidQuery(animalID) || invalidQuery(animalName) || invalidQuery(animalDOB) || invalidQuery(animalMicrochipNum) || invalidQuery(species) || invalidQuery(breed) || invalidQuery(secondaryBreed) || invalidQuery(gender) || invalidQuery(colour) || invalidQuery(secondaryColour) || invalidQuery(litterID) || invalidQuery(photoFileName) || invalidQuery(fostererID) || invalidQuery(surrenderedByID) || invalidQuery(deceasedDate) || invalidQuery(deceasedReason) || invalidQuery(incomingDate)) {
        return res.status(400).send('Invalid query')
    }

    // Fetch existing values
    try {
        const pool = req.pool;

        const currentData = await pool.request()
            .input('animalID', sql.Int, animalID)
            .query('SELECT * FROM animals WHERE animalID = @animalID;')

        const results = currentData.recordset;
        
        animalName = animalName || results[0].animalName;
        animalDOB = animalDOB || results[0].animalDOB;
        animalMicrochipNum = animalMicrochipNum || results[0].animalMicrochipNum;
        species = species || results[0].species;
        breed = breed || results[0].breed;
        secondaryBreed = secondaryBreed || results[0].secondaryBreed;
        gender = gender || results[0].gender;
        colour = colour || results[0].colour;
        secondaryColour = secondaryColour || results[0].secondaryColour;
        litterID = litterID || results[0].litterID;
        photoFileName = photoFileName || results[0].photoFileName;
        fostererID = fostererID || results[0].fostererID;
        surrenderedByID = surrenderedByID || results[0].surrenderedByID;
        desexed = desexed || results[0].desexed;
        awaitingDesex = awaitingDesex || results[0].awaitingDesex;
        inShelter = inShelter || results[0].inShelter;
        inFoster = inFoster || results[0].inFoster;
        awaitingFoster = awaitingFoster || results[0].awaitingFoster;
        underVetCare = underVetCare || results[0].underVetCare;
        deceased = deceased || results[0].deceased;
        deceasedDate = deceasedDate || results[0].deceasedDate;
        deceasedReason = deceasedReason || results[0].deceasedReason;
        incomingDate = incomingDate || results[0].incomingDate;
    
        if (inFoster === true) {
            awaitingFoster = false; 
            inShelter = false;
        }
    }
    catch (err) {
        console.log(err);
        return res.status(400).send(err);
    }

    // Validate typings
    if (typeof(animalName) !== 'string' || animalName.length > 255) {
        return res.status(400).send('Not a valid animal name')
    }
    if (!/^\d{4}-\d{2}-\d{2}$/.test(animalDOB) && animalDOB !== "" && animalDOB !== null) {
        return res.status(400).send('Not a valid DOB')
    }
    if ((typeof(animalMicrochipNum) !== 'string' || animalMicrochipNum.length > 255) && animalMicrochipNum !== null) {
        return res.status(400).send('Not a valid animal microchip number')
    }
    if (typeof(species) !== 'string' || species.length > 255) {
        return res.status(400).send('Not a valid species')
    }
    if ((typeof(breed) !== 'string' || breed.length > 255) && breed !== null) {
        return res.status(400).send('Not a valid breed')
    }
    if ((typeof(secondaryBreed) !== 'string' || secondaryBreed.length > 255) && secondaryBreed !== null) {
        return res.status(400).send('Not a valid secondary breed')
    }
    if ((typeof(gender) !== 'string' || gender.length > 255) && gender !== null) {
        return res.status(400).send('Not a valid gender')
    }
    if ((typeof(colour) !== 'string' || colour.length > 255) && colour !== null) {
        return res.status(400).send('Not a valid colour')
    }
    if ((typeof(secondaryColour) !== 'string' || secondaryColour.length > 255) && secondaryColour !== null) {
        return res.status(400).send('Not a valid secondary colour')
    }
    if (typeof(litterID) !== 'number') {
        if (litterID !== null) {
            return res.status(400).send('Not a valid litter ID')
        }
    }
    if ((typeof(photoFileName) !== 'string' || photoFileName.length > 255) && photoFileName !== null) {
        return res.status(400).send('Not a valid photo file name')
    }
    if (typeof(fostererID) !== 'number') {
        if (fostererID !== null) {
            return res.status(400).send('Not a valid fosterer ID')
        }
    }
    if (typeof(surrenderedByID) !== 'number') {
        if(surrenderedByID !== null ){    
            return res.status(400).send('Not a valid surrenderer ID')
        }
    }   
    if (typeof(desexed) !== 'boolean' && desexed !== null) {
        return res.status(400).send('Not a valid desexed value')
    }
    if (typeof(awaitingDesex) !== 'boolean' && awaitingDesex !== null) {
        return res.status(400).send('Not a valid awaiting desex value')
    }
    if (typeof(inShelter) !== 'boolean' && inShelter !== null) {
        return res.status(400).send('Not a valid in shelter value')
    }
    if (typeof(inFoster) !== 'boolean' && inFoster !== null) {
        return res.status(400).send('Not a valid infoster value')
    }
    if (typeof(awaitingFoster) !== 'boolean' && awaitingFoster !== null) {
        return res.status(400).send('Not a valid awaiting foster value')    
    }
    if (typeof(underVetCare) !== 'boolean' && underVetCare !== null) {
        return res.status(400).send('Not a valid under vet care value')
    }
    if (typeof(deceased) !== 'boolean' && deceased !== null) {
        return res.status(400).send('Not a valid deceased value')
    }
    if (!/^\d{4}-\d{2}-\d{2}$/.test(deceasedDate) && deceasedDate !== "" && deceasedDate !== null) {
        return res.status(400).send('Not a valid deceased date')
    }
    if (deceasedDate === "") {
        deceasedDate = null
    }
    if ((typeof(deceasedReason) !== 'string' || deceasedReason.length > 255) && deceasedReason !== null) {
        return res.status(400).send('Not a valid deceased reason')
    }
    if (!/^\d{4}-\d{2}-\d{2}$/.test(incomingDate) && incomingDate !== "" && incomingDate !== null) {
        return res.status(400).send('Not a valid incoming date')
    }

    if (inFoster === true) {awaitingFoster = false; inShelter = false;}

    // Update the item in the database
    try {
        const pool = req.pool;
        const result = await pool.request()
        .input('animalID', sql.Int, animalID)
        .input('animalName', sql.VarChar(255), animalName)
        .input('animalDOB', sql.VarChar(255), animalDOB)
        .input('animalMicrochipNum', sql.VarChar(255), animalMicrochipNum)
        .input('species', sql.VarChar(255), species)
        .input('breed', sql.VarChar(255), breed)
        .input('secondaryBreed', sql.VarChar(255), secondaryBreed)
        .input('gender', sql.VarChar(255), gender)
        .input('colour', sql.VarChar(255), colour)
        .input('secondaryColour', sql.VarChar(255), secondaryColour)
        .input('litterID', sql.Int, litterID)
        .input('photoFileName', sql.VarChar(255), photoFileName)
        .input('fostererID', sql.Int, fostererID)
        .input('surrenderedByID', sql.Int, surrenderedByID)
        .input('desexed', sql.Bit, desexed)
        .input('awaitingDesex', sql.Bit, awaitingDesex)
        .input('inShelter', sql.Bit, inShelter)
        .input('inFoster', sql.Bit, inFoster)
        .input('awaitingFoster', sql.Bit, awaitingFoster)
        .input('underVetCare', sql.Bit, underVetCare)
        .input('deceased', sql.Bit, deceased)
        .input('deceasedDate', sql.VarChar(255), deceasedDate)
        .input('deceasedReason', sql.VarChar(255), deceasedReason)
        .input('incomingDate', sql.VarChar(255), incomingDate)
        .query('UPDATE animals SET animalName = @animalName, animalDOB = @animalDOB, animalMicrochipNum = @animalMicrochipNum, species = @species, breed = @breed, secondaryBreed = @secondaryBreed, gender = @gender, colour = @colour, secondaryColour = @secondaryColour, litterID = @litterID, photoFileName = @photoFileName, fostererID = @fostererID, surrenderedByID = @surrenderedByID, desexed = @desexed, awaitingDesex = @awaitingDesex, inShelter = @inShelter, inFoster = @inFoster, awaitingFoster = @awaitingFoster, underVetCare = @underVetCare, deceased = @deceased, deceasedDate = @deceasedDate, deceasedReason = @deceasedReason, incomingDate = @incomingDate WHERE animalID = @animalID;')

        console.log(result)
        return res.json({
            updated: true
        })
    } 
    catch (err) {
        console.log(err)
        return res.status(400).send(err)
    }
});


// Delete animal
app.delete('/animals/delete', authenticateToken, async (req, res) => {
    console.log('Deleting animal...')
    let { animalID } = req.body;

    if (!animalID) {
        return res.status(400).send("Animal ID cannot be empty")
    }

    try {
        const pool = req.pool;
        const request = await pool.request()
        .input('animalID', sql.Int, animalID)
        .query('DELETE FROM animals WHERE animalID = @animalID;')

        if (!request) {
            return res.status(400).send("Animal ID not found")
        }
        else {
            return res.json({
                deleted: true
            })
        }
    }
    catch (err) {
        return res.status(400).send(err)
    }
});


// Fetch fosterers
app.get('/fosterers', authenticateToken, async (req, res) => {
    console.log('Fetching fosterers...');

    try {
        const pool = req.pool;
        const results = await pool.request()
        .query('SELECT * FROM fosterers ORDER BY fostererID DESC;')
        if (!results) {
            return res.status(400).send("Fosterers not found")
        }
        else {
            return res.json( results.recordset )
        }
    }
    catch (err) {
        return res.status(400).send(err)
    }
});


// Fetch fosterer by ID
app.post('/fosterers/fosterer', authenticateToken, (req, res) => {
    console.log('Fetching fosterer...');
    let { searchTerm } = req.body;
    var searchQuery = "";

    if (!searchTerm) {
        return res.status(400).send("Search term cannot be empty");
    }

    // Validate query
    if (invalidQuery(searchTerm)) {
        return res.status(400).send('Invalid query');
    }

    if (parseInt(searchTerm)) {
        searchQuery = 'SELECT * FROM fosterers WHERE fostererID = ' + searchTerm + ' ORDER BY fostererID DESC;';
    } else {
        searchQuery = 'SELECT * FROM fosterers WHERE fostererName like \'%' + searchTerm + '%\' ORDER BY fostererID DESC;';
    }
    
    try {
        const pool = req.pool;
        const req = pool.request()
        .query(searchQuery)
        if (!req) {
            return res.status(400).send("Fosterer not found")
        }
        else {
            return res.json( req.recordset )
        }
    }
    catch (err) {
        return res.status(400).send(err)
    }
});


app.post('/fosterers/add', authenticateToken, async (req, res) => {
    console.log('Adding fosterer...')
    let { fostererFirstName, fostererLastName, fostererAddress, fostererTown, fostererPhone, fostererSecondaryPhone, fostererEmail, fostererDOB, fostererGender, advancedNursing, zoonoticDisease, bottleFeeders } = req.body
    if (!fostererFirstName) {
        return res.status(400).send("Fosterer first name cannot be empty")
    }
    if (!fostererLastName) {
        return res.status(400).send("Fosterer last name cannot be empty")
    }

    // Validate query
    if (invalidQuery(fostererFirstName) || invalidQuery(fostererLastName) || invalidQuery(fostererAddress) || invalidQuery(fostererTown) || invalidQuery(fostererPhone) || invalidQuery(fostererSecondaryPhone) || invalidQuery(fostererEmail) || invalidQuery(fostererDOB) || invalidQuery(fostererGender) || invalidQuery(advancedNursing) || invalidQuery(zoonoticDisease) || invalidQuery(bottleFeeders)) {
        return res.status(400).send('Invalid query')
    }   

    // Validate typings
    if (typeof(fostererFirstName) !== 'string' || fostererFirstName.length > 255) {
        return res.status(400).send('Not a valid fosterer first name')
    }
    if (typeof(fostererLastName) !== 'string' || fostererLastName.length > 255) {
        return res.status(400).send('Not a valid fosterer last name')
    }
    if (typeof(fostererAddress) !== 'string' || fostererAddress.length > 255) {
        return res.status(400).send('Not a valid fosterer address')
    }
    if (typeof(fostererTown) !== 'string' || fostererTown.length > 255) {    
        return res.status(400).send('Not a valid fosterer town')
    }
    if (typeof(fostererPhone) !== 'string' || fostererPhone.length > 255) {
        return res.status(400).send('Not a valid fosterer phone')
    }
    if (typeof(fostererSecondaryPhone) !== 'string' || fostererSecondaryPhone.length > 255) {
        return res.status(400).send('Not a valid fosterer mobile')
    }
    if (typeof(fostererEmail) !== 'string' || fostererEmail.length > 255) {
        return res.status(400).send('Not a valid fosterer email')
    }
    if (!/^\d{4}-\d{2}-\d{2}$/.test(fostererDOB)) {
        return res.status(400).send('Not a valid date of birth')
    }
    if (typeof(fostererGender) !== 'string' || fostererGender.length > 255) {
        return res.status(400).send('Not a valid fosterer gender')
    }
    if (typeof(advancedNursing) !== 'boolean') {
        return res.status(400).send('Not a valid advanced nursing value')
    }
    if (typeof(zoonoticDisease) !== 'boolean') {
        return res.status(400).send('Not a valid zoonotic disease value')
    }
    if (typeof(bottleFeeders) !== 'boolean') {
        return res.status(400).send('Not a valid bottle feeders value')
    }

    try {
        const pool = await req.pool;

        const result = await pool.request()
        .input('fostererAddress', fostererAddress)
        .input('fostererTown', fostererTown)
        .input('fostererPhone', fostererPhone)
        .input('fostererSecondaryPhone', fostererSecondaryPhone)
        .input('fostererEmail', fostererEmail)
        .input('fostererDOB', fostererDOB)
        .input('fostererGender', fostererGender)
        .input('advancedNursing', advancedNursing)
        .input('zoonoticDisease', zoonoticDisease)
        .input('bottleFeeders', bottleFeeders)
        .query('INSERT INTO fosterers (fostererFirstName, fostererLastName, fostererAddress, fostererTown, fostererPhone, fostererSecondaryPhone, fostererEmail, fostererDOB, fostererGender, advancedNursing, zoonoticDisease, bottleFeeders) VALUES (@fostererFirstName, @fostererLastName, @fostererAddress, @fostererTown, @fostererPhone, @fostererSecondaryPhone, @fostererEmail, @fostererDOB, @fostererGender, @advancedNursing, @zoonoticDisease, @bottleFeeders)');

        return res.json({created:true});

    } catch (err) {
        console.log(err);
        return res.status(400).send(err);
    }
})

app.patch('/fosterers/update', authenticateToken, async (req, res) => {
    console.log('Updating fosterer...')
    let { fostererID, fostererFirstName, fostererLastName, fostererAddress, fostererTown, fostererPhone, fostererSecondaryPhone, fostererEmail, fostererDOB, fostererGender, advancedNursing, zoonoticDisease, bottleFeeders } = req.body

    if (!fostererID) {
        return res.status(400).send("Fosterer ID cannot be empty")
    }

    // Validate query
    if (invalidQuery(fostererID) || invalidQuery(fostererFirstName) || invalidQuery(fostererLastName) || invalidQuery(fostererAddress) || invalidQuery(fostererTown) || invalidQuery(fostererPhone) || invalidQuery(fostererSecondaryPhone) || invalidQuery(fostererEmail) || invalidQuery(fostererDOB) || invalidQuery(fostererGender) || invalidQuery(advancedNursing) || invalidQuery(zoonoticDisease) || invalidQuery(bottleFeeders)) {
        return res.status(400).send('Invalid query')
    }

    // Fetch existing values
    try {
        const pool = await req.pool;
        const result = await pool.request()
        .input('fostererID', fostererID)
        .query('SELECT * FROM fosterers WHERE fostererID = @fostererID;');

        if (result.recordset.length == 0) {
            return res.status(400).send('Fosterer not found')
        }
        else {
            // update values with current values if not provided in the request body
            fostererFirstName = fostererFirstName || result.recordset[0].fostererFirstName
            fostererLastName = fostererLastName || result.recordset[0].fostererLastName
            fostererAddress = fostererAddress || result.recordset[0].fostererAddress
            fostererTown = fostererTown || result.recordset[0].fostererTown
            fostererPhone = fostererPhone || result.recordset[0].fostererPhone
            fostererSecondaryPhone = fostererSecondaryPhone || result.recordset[0].fostererSecondaryPhone
            fostererEmail = fostererEmail || result.recordset[0].fostererEmail
            fostererDOB = fostererDOB || result.recordset[0].fostererDOB
            fostererGender = fostererGender || result.recordset[0].fostererGender
            advancedNursing = advancedNursing || result.recordset[0].advancedNursing
            zoonoticDisease = zoonoticDisease || result.recordset[0].zoonoticDisease
            bottleFeeders = bottleFeeders || result.recordset[0].bottleFeeders
        }
    } catch (err) {
        console.log(err);
        return res.status(400).send(err);
    }

    // Validate typings
    if (typeof(fostererFirstName) !== 'string' || fostererFirstName.length > 255) {
        return res.status(400).send('Not a valid fosterer first name')
    }
    if (typeof(fostererLastName) !== 'string' || fostererLastName.length > 255) {
        return res.status(400).send('Not a valid fosterer last name')
    }
    if (typeof(fostererAddress) !== 'string' || fostererAddress.length > 255) {
        return res.status(400).send('Not a valid fosterer address')
    }
    if (typeof(fostererTown) !== 'string' || fostererTown.length > 255) {    
        return res.status(400).send('Not a valid fosterer town')
    }
    if (typeof(fostererPhone) !== 'string' || fostererPhone.length > 255) {
        return res.status(400).send('Not a valid fosterer phone')
    }
    if (typeof(fostererSecondaryPhone) !== 'string' || fostererSecondaryPhone.length > 255) {
        return res.status(400).send('Not a valid fosterer mobile')
    }
    if (typeof(fostererEmail) !== 'string' || fostererEmail.length > 255) {
        return res.status(400).send('Not a valid fosterer email')
    }
    if (!/^\d{4}-\d{2}-\d{2}$/.test(fostererDOB)) {
        return res.status(400).send('Not a valid date of birth')
    }
    if (typeof(fostererGender) !== 'string' || fostererGender.length > 255) {
        return res.status(400).send('Not a valid fosterer gender')
    }
    if (typeof(advancedNursing) !== 'boolean') {
        return res.status(400).send('Not a valid advanced nursing value')
    }
    if (typeof(zoonoticDisease) !== 'boolean') {
        return res.status(400).send('Not a valid zoonotic disease value')
    }
    if (typeof(bottleFeeders) !== 'boolean') {
        return res.status(400).send('Not a valid bottle feeders value')
    }

    try {
        await req.pool.request()
            .input('fostererFirstName', fostererFirstName)
            .input('fostererLastName', fostererLastName)
            .input('fostererAddress', fostererAddress)
            .input('fostererTown', fostererTown)
            .input('fostererPhone', fostererPhone)
            .input('fostererSecondaryPhone', fostererSecondaryPhone)
            .input('fostererEmail', fostererEmail)
            .input('fostererDOB', fostererDOB)
            .input('fostererGender', fostererGender)
            .input('advancedNursing', advancedNursing)
            .input('zoonoticDisease', zoonoticDisease)
            .input('bottleFeeders', bottleFeeders)
            .input('fostererID', fostererID)
            .query('UPDATE fosterers SET fostererFirstName = @fostererFirstName, fostererLastName = @fostererLastName, fostererAddress = @fostererAddress, fostererTown = @fostererTown, fostererPhone = @fostererPhone, fostererSecondaryPhone = @fostererSecondaryPhone, fostererEmail = @fostererEmail, fostererDOB = @fostererDOB, fostererGender = @fostererGender, advancedNursing = @advancedNursing, zoonoticDisease = @zoonoticDisease, bottleFeeders = @bottleFeeders WHERE fostererID = @fostererID');
        return res.json({ 
            updated: true
        }) 
    } catch (err) {
        return res.status(400).send(err)
    }

}
);

app.delete('/fosterers/delete', authenticateToken, async (req, res) => {
    console.log('Deleting fosterer...')
    let { fostererID } = req.body
    if (!fostererID) {
        return res.status(400).send("Fosterer ID cannot be empty")
    }

    try {
        const pool = await req.pool;
        const result = await pool.request()
            .input('fostererID', fostererID)
            .query('SELECT * FROM fosterers WHERE fostererID = @fostererID;');

        return res.json({
            deleted: true
        })
    }
    catch (err) {
        return res.status(400).send(err)
    }

});

app.get('/litters', authenticateToken, async (req, res) => {
    console.log('Fetching litters...')

    try {
        const pool = req.pool;
        const result = await pool.request()
            .query('SELECT * FROM litters ORDER BY litterID DESC;');

        return res.json( result.recordset )
    }   
    catch (err) {
        return res.status(400).send(err)
    }


});

app.post('/litters/litter', authenticateToken, async (req, res) => {
    console.log('Fetching litter...')
    let { searchTerm } = req.body;

    if (!searchTerm) {
        return res.status(400).send("Search term cannot be empty")
    }

    if (invalidQuery(searchTerm)) {
        return res.status(400).send('Invalid query')
    }

    if(parseInt(searchTerm)){
            searchQuery = 'SELECT * FROM litters WHERE litterID = ' + searchTerm + ' ORDER BY litterID DESC;'
        }
    else{
        searchQuery = 'SELECT * FROM litters WHERE litterName LIKE \`%' + searchTerm + '%\` ORDER BY litterID DESC;'
    }

    try {
        const pool = req.pool;
        const result = await pool.request()
            .query(searchQuery);
        
            return res.json( result.recordset )
    }
    catch (err) {
        return res.status(400).send(err)
    }
});

app.post('/litters/add', authenticateToken, async (req, res) => {
    console.log('Adding litter...')
    let { litterName, motherID, litterNotes } = req.body;
    if (!litterName) {
        return res.status(400).send("Litter name cannot be empty")
    }

    if (invalidQuery(litterName) || invalidQuery(motherID)) {
        return res.status(400).send('Invalid query')
    }

    try {
        const pool = req.pool;
        const result = await pool.request()
            .input('litterName', litterName)
            .input('motherID', motherID)
            .input('litterNotes', litterNotes)
            .query('INSERT INTO litters (litterName, motherID, litterNotes) VALUES (@litterName, @motherID, @litterNotes);');
        
        return res.json({
            created: true
        })
    } catch (err) {
        return res.status(400).send(err)
    }

})

app.patch('/litters/update', authenticateToken, async (req, res) => {
    console.log('Updating litter...')  
    let { litterID, litterName, motherID, litterNotes } = req.body
    if (!litterID) {
        return res.status(400).send("Litter ID cannot be empty")
    }

    if (invalidQuery(litterID) || invalidQuery(litterName) || invalidQuery(motherID)) {
        return res.status(400).send('Invalid query')
    }

    // Fetch existing values
    try {
        const pool = req.pool;
        const interimData = await pool.request()
            .input('litterID', litterID)
            .query('SELECT * FROM litters WHERE litterID = @litterID;');

        results = interimData.recordset
        litterID = litterID || results[0].litterID
        litterName = litterName || results[0].litterName
        motherID = motherID || results[0].motherID
        litterNotes = litterNotes || results[0].litterNotes
    }
    catch (err) {
        return res.status(400).send(err)
    }

    // Validate typing
    if (typeof(litterName) !== 'string' || litterName.length > 255) {
        return res.status(400).send('Not a valid litter name')
    }
    if (typeof(motherID) !== 'integer') {
        return res.status(400).send('Not a valid mother ID')
    }
    if (typeof(litterNotes) !== 'string' || litterNotes.length > 255) {
        return res.status(400).send('Not a valid litter note')
    }

    // Update the item in the database
    try {
        const pool = req.pool;
        const result = await pool.request()
            .input('litterID', litterID)
            .input('litterName', litterName)
            .input('motherID', motherID)
            .input('litterNotes', litterNotes)
            .query('UPDATE litters SET litterName = @litterName, motherID = @motherID, litterNotes = @litterNotes WHERE litterID = @litterID;');

        return res.json({
            updated: true
        })
    }
    catch (err) {
        return res.status(400).send(err)
    }
});

app.delete('/litters/delete', authenticateToken, async (req, res) => {
    console.log('Deleting litter...')  
    let { litterID } = req.body
    if (!litterID) {
        return res.status(400).send("Litter ID cannot be empty")
    }
    if (typeof(litterID) !== 'integer') {
        return res.status(400).send('Not a valid litter ID')
    }

    try {
        const pool = req.pool;
        const result = await pool.request()
            .input('litterID', litterID)
            .query('DELETE FROM litters WHERE litterID = @litterID;');
        
        return res.json({
            deleted: true
        })
    }
    catch (err) {
        return res.status(400).send(err)
    }
});

app.get('/volunteers', authenticateToken, async (req, res) => {
    console.log('Fetching volunteers...')

    try {
        const pool = req.pool;
        const result = await pool.request()
            .query('SELECT * FROM volunteers ORDER BY volunteerID DESC;');
        
        return res.json( result.recordset )
    }
    catch (err) {
        return res.status(400).send(err)
    }
});

app.post('/volunteers/volunteer', authenticateToken, async (req, res) => {
    console.log('Finding volunteers...');
    let { searchTerm } = req.body;    
    if (!searchTerm) {
        return res.status(400).send("Search term cannot be empty")
    }
    
    if (invalidQuery(searchTerm)) {
        return res.status(400).send('Invalid query')
    }

    if(parseInt(searchTerm)){
        searchQuery = 'SELECT * FROM volunteers WHERE volunteerID = ' + searchTerm + ' ORDER BY volunteerID DESC;'
    }
    else {
        searchQuery = 'SELECT * FROM volunteers WHERE volunteerName LIKE \`%' + searchTerm + '%\` ORDER BY volunteerID DESC;'
    }

    try {
        const pool = req.pool;
        const result = await pool.request()
            .query(searchQuery);
        
        return res.json({ created: true })
    }
    catch (err) {
        return res.status(400).send(err)
    }
});

app.post('/volunteers/add', authenticateToken, async (req, res) => {
    console.log('Adding volunteer...')
    let { volunteerFirstName, volunteerLastName, volunteerAddress, volunteerTown, volunteerPhone, volunteerSecondaryPhone, volunteerEmail, volunteerDOB, volunteerGender, volunteerCheckbox1, volunteerCheckbox2, volunteerCheckbox3, volunteerCheckbox4 } = req.body;
    if(!volunteerFirstName || !volunteerLastName || !volunteerPhone || !volunteerDOB) {
        return res.status(400).send("Missing required fields")
    }
    if (invalidQuery(volunteerFirstName) || invalidQuery(volunteerLastName) || invalidQuery(volunteerAddress) || invalidQuery(volunteerTown) || invalidQuery(volunteerPhone) || invalidQuery(volunteerSecondaryPhone) || invalidQuery(volunteerEmail) || invalidQuery(volunteerDOB) || invalidQuery(volunteerGender) || invalidQuery(volunteerCheckbox1) || invalidQuery(volunteerCheckbox2) || invalidQuery(volunteerCheckbox3) || invalidQuery(volunteerCheckbox4)) {
        return res.status(400).send('Invalid query')
    }

    // Validate typing
    if (typeof(volunteerFirstName) !== 'string' || volunteerFirstName.length > 255) {
        return res.status(400).send('Not a valid volunteer first name')
    }
    if (typeof(volunteerLastName) !== 'string' || volunteerLastName.length > 255) {
        return res.status(400).send('Not a valid volunteer last name')
    }
    if (typeof(volunteerAddress) !== 'string' || volunteerAddress.length > 255) {
        return res.status(400).send('Not a valid volunteer address')
    }
    if (typeof(volunteerTown) !== 'string' || volunteerTown.length > 255) {
        return res.status(400).send('Not a valid volunteer town')
    }
    if (typeof(volunteerPhone) !== 'string' || volunteerPhone.length > 255) {
        return res.status(400).send('Not a valid volunteer phone')
    }
    if (typeof(volunteerSecondaryPhone) !== 'string' || volunteerSecondaryPhone.length > 255) {
        return res.status(400).send('Not a valid volunteer secondary phone')
    }
    if (typeof(volunteerEmail) !== 'string' || volunteerEmail.length > 255) {
        return res.status(400).send('Not a valid volunteer email')
    }
    if (!/^\d{4}-\d{2}-\d{2}$/.test(volunteerDOB)) {
        return res.status(400).send('Not a valid date of birth')
    }
    if (typeof(volunteerGender) !== 'string' || volunteerGender.length > 255) {
        return res.status(400).send('Not a valid volunteer gender')
    }
    if (typeof(volunteerCheckbox1) !== 'boolean') {
        return res.status(400).send('Not a valid volunteer checkbox 1')
    }
    if (typeof(volunteerCheckbox2) !== 'boolean') {
        return res.status(400).send('Not a valid volunteer checkbox 2')
    }
    if (typeof(volunteerCheckbox3) !== 'boolean') {
        return res.status(400).send('Not a valid volunteer checkbox 3')
    }
    if (typeof(volunteerCheckbox4) !== 'boolean') {
        return res.status(400).send('Not a valid volunteer checkbox 4')
    }

    // Update database
    try {
        const pool = req.pool;
        const result = await pool.request()
            .query('INSERT INTO volunteers SET ?', {
                volunteerFirstName: volunteerFirstName,
                volunteerLastName: volunteerLastName,
                volunteerAddress: volunteerAddress,
                volunteerTown: volunteerTown,
                volunteerPhone: volunteerPhone,
                volunteerSecondaryPhone: volunteerSecondaryPhone,
                volunteerEmail: volunteerEmail,
                volunteerDOB: volunteerDOB,
                volunteerGender: volunteerGender,
                volunteerCheckbox1: volunteerCheckbox1,
                volunteerCheckbox2: volunteerCheckbox2,
                volunteerCheckbox3: volunteerCheckbox3,
                volunteerCheckbox4: volunteerCheckbox4
            });
        
        return res.json({ created: true })
    }
    catch (err) {
        return res.status(400).send(err)
    }
});

app.patch('/volunteers/update', authenticateToken, async (req, res) => {
    console.log('Updating volunteer...')
    let { volunteerID, volunteerFirstName, volunteerLastName, volunteerAddress, volunteerTown, volunteerPhone, volunteerSecondaryPhone, volunteerEmail, volunteerDOB, volunteerGender, volunteerCheckbox1, volunteerCheckbox2, volunteerCheckbox3, volunteerCheckbox4 } = req.body;
    if(!volunteerID) {
        return res.status(400).send("Missing required fields")
    }
    if (typeof(volunteerID) !== 'number') {
        return res.status(400).send('Not a valid volunteer ID')
    }
    if ( invalidQuery(volunteerFirstName) || invalidQuery(volunteerLastName) || invalidQuery(volunteerAddress) || invalidQuery(volunteerTown) || invalidQuery(volunteerPhone) || invalidQuery(volunteerSecondaryPhone) || invalidQuery(volunteerEmail) || invalidQuery(volunteerDOB) || invalidQuery(volunteerGender)) {
        return res.status(400).send('Invalid query')
    }

    // Fetch existing volunteer
    try {
        const pool = req.pool;
        const interimData = await pool.request()
            .input('volunteerID', sql.Int, volunteerID)
            .query('SELECT * FROM volunteers WHERE volunteerID = @volunteerID;');

        results = interimData.recordset;

        volunteerFirstName = volunteerFirstName || results[0].volunteerFirstName;
        volunteerLastName = volunteerLastName || results[0].volunteerLastName;
        volunteerAddress = volunteerAddress || results[0].volunteerAddress;
        volunteerTown = volunteerTown || results[0].volunteerTown;
        volunteerPhone = volunteerPhone || results[0].volunteerPhone;
        volunteerSecondaryPhone = volunteerSecondaryPhone || results[0].volunteerSecondaryPhone;
        volunteerEmail = volunteerEmail || results[0].volunteerEmail;
        volunteerDOB = volunteerDOB || results[0].volunteerDOB;
        volunteerGender = volunteerGender || results[0].volunteerGender;
        volunteerCheckbox1 = volunteerCheckbox1 || results[0].volunteerCheckbox1;
        volunteerCheckbox2 = volunteerCheckbox2 || results[0].volunteerCheckbox2;
        volunteerCheckbox3 = volunteerCheckbox3 || results[0].volunteerCheckbox3;
        volunteerCheckbox4 = volunteerCheckbox4 || results[0].volunteerCheckbox4;
    }
    catch (err) {
        return res.status(400).send(err)
    }

    // Validate typing
    if (typeof(volunteerFirstName) !== 'string' || volunteerFirstName.length > 255) {
        return res.status(400).send('Not a valid volunteer first name')
    }
    if (typeof(volunteerLastName) !== 'string' || volunteerLastName.length > 255) {
        return res.status(400).send('Not a valid volunteer last name')
    }
    if (typeof(volunteerAddress) !== 'string' || volunteerAddress.length > 255) {
        return res.status(400).send('Not a valid volunteer address')
    }
    if (typeof(volunteerTown) !== 'string' || volunteerTown.length > 255) {
        return res.status(400).send('Not a valid volunteer town')
    }
    if (typeof(volunteerPhone) !== 'string' || volunteerPhone.length > 255) {
        return res.status(400).send('Not a valid volunteer phone')
    }
    if (typeof(volunteerSecondaryPhone) !== 'string' || volunteerSecondaryPhone.length > 255) {
        return res.status(400).send('Not a valid volunteer secondary phone')
    }
    if (typeof(volunteerEmail) !== 'string' || volunteerEmail.length > 255) {
        return res.status(400).send('Not a valid volunteer email')
    }
    if (!/^\d{4}-\d{2}-\d{2}$/.test(volunteerDOB)) {
        return res.status(400).send('Not a valid date of birth')
    }
    if (typeof(volunteerGender) !== 'string' || volunteerGender.length > 255) {
        return res.status(400).send('Not a valid volunteer gender')
    }
    if (typeof(volunteerCheckbox1) !== 'boolean') {
        return res.status(400).send('Not a valid volunteer checkbox 1')
    }
    if (typeof(volunteerCheckbox2) !== 'boolean') {
        return res.status(400).send('Not a valid volunteer checkbox 2')
    }
    if (typeof(volunteerCheckbox3) !== 'boolean') {
        return res.status(400).send('Not a valid volunteer checkbox 3')
    }
    if (typeof(volunteerCheckbox4) !== 'boolean') {
        return res.status(400).send('Not a valid volunteer checkbox 4')
    }

    // Update database
    try {
        const results = await pool.request()
            .input('volunteerID', sql.Int, volunteerID)
            .input('volunteerFirstName', sql.VarChar(255), volunteerFirstName)
            .input('volunteerLastName', sql.VarChar(255), volunteerLastName)
            .input('volunteerAddress', sql.VarChar(255), volunteerAddress)
            .input('volunteerTown', sql.VarChar(255), volunteerTown)
            .input('volunteerPhone', sql.VarChar(255), volunteerPhone)
            .input('volunteerSecondaryPhone', sql.VarChar(255), volunteerSecondaryPhone)
            .input('volunteerEmail', sql.VarChar(255), volunteerEmail)
            .input('volunteerDOB', sql.VarChar(255), volunteerDOB)
            .input('volunteerGender', sql.VarChar(255), volunteerGender)
            .input('volunteerCheckbox1', sql.Bit, volunteerCheckbox1)
            .input('volunteerCheckbox2', sql.Bit, volunteerCheckbox2)
            .input('volunteerCheckbox3', sql.Bit, volunteerCheckbox3)
            .input('volunteerCheckbox4', sql.Bit, volunteerCheckbox4)   
            .query('UPDATE volunteers SET volunteerFirstName = @volunteerFirstName, volunteerLastName = @volunteerLastName, volunteerAddress = @volunteerAddress, volunteerTown = @volunteerTown, volunteerPhone = @volunteerPhone, volunteerSecondaryPhone = @volunteerSecondaryPhone, volunteerEmail = @volunteerEmail, volunteerDOB = @volunteerDOB, volunteerGender = @volunteerGender, volunteerCheckbox1 = @volunteerCheckbox1, volunteerCheckbox2 = @volunteerCheckbox2, volunteerCheckbox3 = @volunteerCheckbox3, volunteerCheckbox4 = @volunteerCheckbox4 WHERE volunteerID = @volunteerID;');

            return res.json({updated: true})
    }
    catch {
        return res.status(400).send('Error updating volunteer')
    }
});

app.delete('/volunteers/delete', authenticateToken, async (req, res) => {
    console.log('Deleting volunteer...')
    let { volunteerID } = req.body;
    if(!volunteerID) {
        return res.status(400).send("Missing required fields")
    }   

    // Validate typing
    if (typeof(volunteerID) !== 'number') {
        return res.status(400).send('Not a valid volunteer ID')
    }

    // Delete from database
    try {
        const pool = req.pool;
        const result = await pool.request()
            .input('volunteerID', sql.Int, volunteerID)
            .query('DELETE FROM volunteers WHERE volunteerID = @volunteerID;');
            
            return res.json({deleted: true})
    }
    catch (err) {
        return res.status(400).send('Error deleting volunteer: ' + err)
    }
});

app.get('/weights/weights', authenticateToken, async (req, res) => {
    console.log('Getting weights...')
    try {
        const pool = req.pool;
        const result = await pool.request()
            .query('SELECT * FROM weights ORDER BY weightID DESC;');

        return res.json(result.recordset);
    }
    catch (err) {
        return res.status(400).send(err)
    } 
});

app.get('/weights/weight', authenticateToken, async (req, res) => {
    console.log('Getting weight...')
    let { animalID } = req.query;
    if(!animalID) {
        return res.status(400).send("Missing required fields")
    }
    if (animalID.match(/^\d+$/) === false) {
        return res.status(400).send('Not a valid animal ID')
    }

    try {
        const pool = req.pool;
        const result = await pool.request()
            .input('animalID', sql.Int, animalID)
            .query('SELECT * FROM weights WHERE animalID = @animalID ORDER BY weightID DESC;');
        return res.json(result.recordset);
    }
    catch (err) {
        return res.status(400).send(err)
    }
});

app.post('/weights/create', authenticateToken, async (req, res) => {
    console.log('Creating weight...')
    let { animalID, weight, note, readingTakenBy } = req.body;
    const currentDateTime = new Date().toISOString().replace('T', ' ').replace('Z', '');
    if(!weight || !readingTakenBy || !animalID) {
        return res.status(400).send("Missing required fields")
    }
    if ( invalidQuery(note) || invalidQuery(readingTakenBy) ) {
        return res.status(400).send('Invalid query')
    }

    // Validate typing    
    if (typeof(weight) !== 'number') {
        return res.status(400).send('Not a valid weight value')
    }
    if (typeof(note) !== 'string' || note.length > 255) {
        return res.status(400).send('Not a valid note')
    }
    if (typeof(readingTakenBy) !== 'string' || readingTakenBy.length > 255) {
        return res.status(400).send('Not a valid reading taken by')
    }

    // Create in database
    try {
        const pool = req.pool;
        const result = await pool.request()
            .input('animalID', sql.Int, animalID)
            .input('weight', sql.Float, weight)
            .input('note', sql.VarChar(255), note)
            .input('readingTakenBy', sql.VarChar(255), readingTakenBy)
            .input('readingDateTime', sql.VarChar(255), currentDateTime)
            .query('INSERT INTO weights (animalID, weight, note, readingTakenBy, readingDateTime) VALUES (@animalID, @weight, @note, @readingTakenBy, @readingDateTime);');

        return res.json({created: true})
    }
    catch (err) {
        return res.status(400).send(err)
    }
});

app.patch('/weights/update', authenticateToken, async (req, res) => {
    console.log('Updating weight...')
    let { weightID, animalID, weight, note, readingTakenBy } = req.body;
    const currentDateTime = new Date().toISOString();

    if(!weightID) {
        return res.status(400).send("Missing required fields")
    }
    if ( invalidQuery(weight) || invalidQuery(note) || invalidQuery(readingTakenBy)) {
        return res.status(400).send('Invalid query')
    }
    if (typeof(weightID) !== 'number') {
        return res.status(400).send('Not a valid weight ID')
    }

    // Fetch existing weight from database and update variables if not present in the request
    try {
        const pool = req.pool;
        const interimData = await pool.request()
            .input('weightID', sql.Int, weightID)
            .query('SELECT * FROM weights WHERE weightID = @weightID;');
        if (interimData.recordset.length > 0) {
            animalID = animalID || interimData.recordset[0].animalID
            weight = weight || interimData.recordset[0].weight
            note = note || interimData.recordset[0].note
            readingTakenBy = readingTakenBy || interimData.recordset[0].readingTakenBy
        }
    }
    catch (err) {
        return res.status(400).send(err)
    }

    // Validate typing
    if (typeof(animalID) !== 'number') {
        return res.status(400).send('Not a valid animal ID')
    }
    if (typeof(weight) !== 'number') {
        return res.status(400).send('Not a valid weight value')
    }
    if (typeof(note) !== 'string' || note.length > 255) {
        return res.status(400).send('Not a valid note')
    }
    if (typeof(readingTakenBy) !== 'string' || readingTakenBy.length > 255) {
        return res.status(400).send('Not a valid reading taken by')
    }

    // Update database
    try {
        const pool = req.pool;
        const result = await pool.request()
            .input('animalID', sql.Int, animalID)
            .input('weight', sql.Float, weight)
            .input('note', sql.NVarChar(255), note)
            .input('readingTakenBy', sql.NVarChar(255), readingTakenBy)
            .input('readingDateTime', sql.DateTime, currentDateTime)
            .input('weightID', sql.Int, weightID)
            .query('UPDATE weights SET animalID = @animalID, weight = @weight, note = @note, readingTakenBy = @readingTakenBy, readingDateTime = @readingDateTime WHERE weightID = @weightID;');
        return res.json({
            updated: true
        })
    } catch (err) {
        return res.status(400).send(err)
    }  
});

app.delete('/weights/delete', authenticateToken, async (req, res) => {
    console.log('Deleting weight...')
    let { weightID } = req.body;
    if(!weightID) {
        return res.status(400).send("Missing required fields")
    }

    // Validate typing
    if (typeof(weightID) !== 'number') {
        return res.status(400).send('Not a valid weight ID')
    }

    // Delete from database
    try {
        const pool = req.pool;
        const result = await pool.request()
            .input('weightID', sql.Int, weightID)
            .query('DELETE FROM weights WHERE weightID = @weightID;');
        
        return res.json({deleted: true})
    }
    catch (err) {
        return res.status(400).send('Error deleting weight: ' + err)
    }
});
