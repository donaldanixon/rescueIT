const express = require('express');
const cors = require('cors');
const mysql = require('mysql');
const bcrypt = require('bcrypt');
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
app.use(cors());
app.listen(8080, () => {
    console.log('Listening on port 8080')
    }
);

// Routes
// - Front page
app.get('/', (req, res) => {
    res.send('Welcome to the RescueIt API!');
    }
);

// - Login
app.post('/users/login', (req, res) => {
    console.log(req.query)
    let { username, password } = req.query;
    if (!username) {
        return res.send("Username cannot be empty")
    }
    if (!password) {
        return res.send("Password cannot be empty")
    }
    console.log('Logging in ' + username)
    connection.query('SELECT * FROM users WHERE username = ?', [username], (err, results) => {
        if (err) {
            return res.send(err)
        }
        else {
            if (results.length === 0) {
                return res.send('User not found');
            }
            bcrypt.compare(password, results[0].userpswd, (err, result) => {
                
                if (err) {
                    return res.send(err)
                }
                else {
                    if (result === true){
                        console.log('Login successful')
                        return res.json({
                            user: results[0].username,
                            role: results[0].userrole
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
})

// - Register
app.get('/users/register', (req, res) => {
    console.log('Registering user...')
        let { username, password, userrole } = req.query;
        
        // Ensure no empty fields
        if (!username) {
            return res.send("Username cannot be empty")
        }
        if (!password) {
            return res.send("Password cannot be empty")
        }
        if (!userrole) {
            return res.send("User role cannot be empty")
        }

        // Validate username to check for uniqueness
        connection.query('SELECT * FROM users WHERE username = ?', [username], (err, results) => {
            if (err) {
                return res.send(err)
            }
            else if (results.length > 0) {
                return res.send('Username already exists')
            }
        })

        // Encrypt password and insert into database
        bcrypt.hash(password, 10, (err, hash) => {
            if (err) {
                return res.send(err)
            }
            connection.query('INSERT INTO users (username, userpswd, userrole) VALUES (?, ?, ?)', [username, hash, userrole], (err, results) => {
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
})

// - List users
app.get('/users', (req, res) => {
    console.log('Fetching users...')
    connection.query(getUsersQuery, (err, results) => {
        if(err){
            return res.send(err)
        }
        else {
            return res.json({
                data: results
            })
        }
    })
}
)

// - Update password
app._router.get('/users/updatepassword', (req, res) => {
    console.log('Updating password...')
    let { username, oldpassword, newpassword } = req.query;
    if (!username) {
        return res.send("Username cannot be empty")
    }
    if (!oldpassword) {
        return res.send("Old Password cannot be empty")
    }
    if (!newpassword) {
        return res.send("New Password cannot be empty")
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