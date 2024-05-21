const express = require('express');
const cors = require('cors');
const mysql = require('mysql');
const bcrypt = require('bcrypt');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const jwtSecret = process.env.RESCUEITJWTsecret;
const rescueITDBpassword = process.env.RESCUEITDBpassword;

// SQL Queries
const getUsersQuery = 'SELECT * FROM users;';

// SQL Connection
const connection = mysql.createConnection({
    host: 'db-rescueit.cho2c4gw4he8.us-east-1.rds.amazonaws.com',
    user: 'admin',
    password: rescueITDBpassword,
    database: 'RESCUEITDB',
    port: '3306'
})
connection.connect(err => {
    if (err) {
        console.log(err);
        return err;
    }
});

// Setup Express App
const app = express();

const limiter = rateLimit({
    windowMs:  60 * 1000, // 1 minutes
    max: 20,
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res, next, options) => {
        res.status(429).json({
          message: 'Too many requests, please try again later.',
        });
    }
});

const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
  
    if (!token) return res.sendStatus(401);
  
    jwt.verify(token, jwtSecret, (err, user) => {
      if (err) return res.sendStatus(403);
      req.user = user;
      next();
    });
};

app.use(limiter);
app.use(cors());
app.use(express.json());
app.listen(8080, () => {
    console.log('Listening on port 8080')
    }
);

// Helper functions
function invalidQuery(query) {
    // Define a regular expression pattern to match SQL keywords followed by a space
    const sqlKeywords = /\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|TRUNCATE|REPLACE|GRANT|REVOKE|=)\s+/i;
    
    // Test the query string against the regular expression pattern
    return sqlKeywords.test(query);
}

// Routes
// - Front page
app.get('/', (req, res) => {
    res.send('Welcome to the RescueIt API!');
    }
);

// - Login
app.post('/users/login', (req, res) => {
    let { username, password } = req.body;
    if (!username) {
        return res.status(400).send("Username cannot be empty")
    }
    if (!password) {
        return res.status(400).send("Password cannot be empty")
    }
    if (invalidQuery(username) || invalidQuery(password)) {
        return res.status(400).send('Invalid query')
    }
    console.log('Logging in ' + username)
    connection.query('SELECT * FROM users WHERE username = ?', [username], (err, results) => {
        if (err) {
            return res.status(400).send(err)
        }
        else {
            console.log(results)
            if (results.length === 0) {
                return res.status(401).send('User not found');
            }
            bcrypt.compare(password, results[0].userpswd, (err, result) => {
                
                if (err) {
                    return res.status(400).send(err)
                }
                else {
                    if (result === true){
                        console.log('Login successful')
                        const token = jwt.sign({userId: results[0].userID, role: results[0].userrole, userName: results[0].username}, jwtSecret, {expiresIn: '1h'});
                        return res.json({ 
                            token: token,
                            userId: results[0].userID, 
                            role: results[0].userrole, 
                            userName: results[0].username
                        });
                    }
                    else {
                        console.log('Incorrect password')
                        return res.status(401).send('Incorrect password')
                    }
                }
            })
        }
    });
})

// - Register
app.get('/users/register', authenticateToken, (req, res) => {
    console.log('Registering user...')
        let { username, password, userrole } = req.body;
        
        // Ensure no empty fields
        if (!username) {
            return res.status(400).send("Username cannot be empty")
        }
        if (!password) {
            return res.status(400).send("Password cannot be empty")
        }
        if (!userrole) {
            return res.status(400).send("User role cannot be empty")
        }

        // Validate query
        if (invalidQuery(username) || invalidQuery(password) || invalidQuery(userrole)) {
            return res.status(400).send('Invalid query')
        }

        // Validate username to check for uniqueness
        connection.query('SELECT * FROM users WHERE username = ?', [username], (err, results) => {
            if (err) {
                return res.status(400).send(err)
            }
            else if (results.length > 0) {
                return res.status(401).send('Username already exists')
            }
        })

        // Encrypt password and insert into database
        bcrypt.hash(password, 10, (err, hash) => {
            if (err) {
                return res.status(400).send(err)
            }
            connection.query('INSERT INTO users (username, userpswd, userrole) VALUES (?, ?, ?)', [username, hash, userrole], (err, results) => {
                if (err) {
                    return res.status(400).send(err)
                }
                else {
                    return res.json({
                        user: username
                    })
                }
            })
        })
})

// - List users
app.get('/users', authenticateToken, (req, res) => {
    console.log('Fetching users...')
    connection.query(getUsersQuery, (err, results) => {
        if(err){
            return res.status(400).send(err)
        }
        else {
            return res.json({ results })
        }
    })
}
)

// - Update password
app.get('/users/updatepassword', authenticateToken, (req, res) => {
    console.log('Updating password...')
    let { username, oldpassword, newpassword } = req.body;
    if (!username) {
        return res.send("Username cannot be empty")
    }
    if (!oldpassword) {
        return res.send("Old Password cannot be empty")
    }
    if (!newpassword) {
        return res.send("New Password cannot be empty")
    }

    // Validate query
    if (invalidQuery(username) || invalidQuery(oldpassword) || invalidQuery(newpassword)) {
        return res.send('Invalid query')
    }

    connection.query('SELECT * FROM users WHERE username = ?', [username], (err, results) => {
        if (err) {
            return res.send(err)
        }
        else {
            bcrypt.compare(password, results[0].userpswd, (err, result) => {
                
                if (err) {
                    return res.send(err)
                }
                else {
                    if (result === true){
                        console.log('Old password matches, updating password...')
                        bcrypt.hash(newpassword, 10, (err, hash) => {
                            if (err) {
                                return res.send(err)
                            }
                            connection.query('UPDATE users SET userpswd = ? WHERE username = ?', [hash, username], (err, res) => {
                                if (err) {
                                    return res.send(err)
                                }
                                else {
                                    return res.json({
                                        user: username
                                    })
                                }
                            })
                        })
                    }
                    else {
                        console.log('Incorrect password')
                        return res.send('Incorrect password')
                    }
                }
            })
        }
    });
}
)

// - List all animals
app.get('/animals', authenticateToken, (req, res) => {
    console.log('Fetching animals...')
    connection.query('SELECT * FROM animals', (err, results) => {       
        if(err){
            return res.send(err)
        }
        else {
            return res.json({ results })
        }})    
}
)

// - Add animal
app.post('/animals/add', authenticateToken, (req, res) => {
    console.log('Adding animal...')
    let { animalName, animalDOB, animalMicrochipNum, species, breed, gender, colour, litterID, photoFileName, fostererID, surrenderedByID, desexed, awaitingDesex, awaitingFoster, underVetCare } = req.body;
    if (!animalName) {
        return res.send("Animal name cannot be empty")
    }
    if (!species) {
        return res.send("Species cannot be empty")
    }

    // Validate query
    if (invalidQuery(animalName) || invalidQuery(species)) {
        return res.send('Invalid query')
    }

    // Insert into database
    connection.query('INSERT INTO animals (animalName, animalDOB, animalMicrochipNum, species, breed, gender, colour, litterID, photoFileName, fostererID, surrenderedByID, desexed, awaitingDesex, awaitingFoster, underVetCare) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)', [animalName, animalDOB, animalMicrochipNum, species, breed, gender, colour, litterID, photoFileName, fostererID, surrenderedByID, desexed, awaitingDesex, awaitingFoster, underVetCare], (err, results) => {
        if (err) {
            return res.send(err)
        }
        else {
            return res.json({
                animalName: animalName
            })
        }
    })
}
)

// - Find animal
app.post('/animals/animal', authenticateToken, (req, res) => {
    console.log('Fetching animal...')
    let { searchTerm, searchType } = req.body;
    var searchQuery = "";

    if (!searchTerm) {
        return res.send("Search term cannot be empty")
    }

    if (!searchType) {
        return res.send("Search type cannot be empty")
    }

    // Validate query
    if (invalidQuery(searchTerm) || invalidQuery(searchType)) {
        return res.send('Invalid query')
    }

    if (searchType === "Animal") {
        if(parseInt(searchTerm)){
            searchQuery = 'SELECT * FROM animals WHERE animalID = ' + searchTerm + ' ORDER BY animalID DESC;'
        }
        else{
            searchQuery = 'SELECT * FROM animals WHERE animalName like \'%' + searchTerm + '%\' ORDER BY animalID DESC;'
        }
    }
    else if (searchType === "Litter") {
        if(parseInt(searchTerm)){
            searchQuery = 'SELECT * FROM animals WHERE litterID = ' + searchTerm +' ORDER BY animalID DESC;'
        }
        else{
            searchQuery = 'SELECT * FROM animals WHERE litterID IN (SELECT litterID FROM litters WHERE litterName like \'%' + searchTerm + '%\') ORDER BY animalID DESC;'
        }
    }
    else if (searchType === "Fosterer") {
        if(parseInt(searchTerm)){
            searchQuery = 'SELECT * FROM animals WHERE fostererID = ' + searchTerm + ' ORDER BY animalID DESC;'
        }
        else{
            searchQuery = 'SELECT * FROM animals WHERE fostererID IN (SELECT fostererID FROM fosterers WHERE fostererName like \'%' + searchTerm + '%\') ORDER BY animalID DESC;'
        }
    }
    console.log(searchQuery)
    connection.query(searchQuery, (err, results) => {       
        if(err){
            return res.send(err)
        }
        else {
            return res.json({ results })
        }})    
}
)

app.get('/fosterers', authenticateToken, (req, res) => {
    console.log('Fetching fosterers...')
    connection.query('SELECT * FROM fosterers', (err, results) => {
        if(err){
            return res.send(err)
        }
        else {
            return res.json({ results })
        }
    })  
}  
);