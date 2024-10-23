const express = require('express')
const path = require('path')

const {open} = require('sqlite')
const sqlite3 = require('sqlite3')

const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')

const dbPath = path.join(__dirname, 'mydb.db')
const app = express()

app.use(express.json())

let db = null

const initializeDBAndServer = async () => {
  try {
    db = await open({filename: dbPath, driver: sqlite3.Database})
    app.listen(3000, () => {
      console.log('Server Running at http://localhost:3000/')
    })
  } catch (e) {
    console.log(`DB Error: ${e.message}`)
    process.exit(-1)
  }
}
initializeDBAndServer()

// users registration

app.post('/users/', async (request, response) => {
  const {username, name, password} = request.body

  try {
    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10)

    
    const selectUserQuery = `SELECT * FROM users WHERE username = ?`
    const dbUser = await db.get(selectUserQuery, [username])

    if (dbUser === undefined) {
     
      const createUserQuery = `
        INSERT INTO 
          users (username, name, password) 
        VALUES (?, ?, ?)`

      const dbResponse = await db.run(createUserQuery, [
        username,
        name,
        hashedPassword,
      ])
      const newUserId = dbResponse.lastID

      response.status(201).send(`Created new user with ID: ${newUserId}`)
    } else {
      response.status(400).send('User already exists')
    }
  } catch (error) {
    console.error(`Error registering user: ${error.message}`)
    response.status(500).send('Internal Server Error')
  }
})

//login api

app.post('/login', async (request, response) => {
  const {username, password} = request.body

  try {
    const selectUserQuery = `SELECT * FROM users WHERE username = ?`
    const dbUser = await db.get(selectUserQuery, [username])

    if (dbUser === undefined) {
      return response.status(400).send({error: 'Invalid User'})
    }

    const isPasswordMatched = await bcrypt.compare(password, dbUser.password)
    if (isPasswordMatched) {
      const payload = {username: username}
      const jwtToken = jwt.sign(payload, 'MY_SECRET_TOKEN') // Use an environment variable for secret

      return response.send({jwtToken})
    } else {
      return response.status(400).send({error: 'Invalid Password'})
    }
  } catch (error) {
    console.error(`Error during login: ${error.message}`)
    return response.status(500).send({error: 'Internal Server Error'})
  }
})

// authentication token

const authenticationToken = (request, response, next) => {
  let jwtToken
  const authHeader = request.headers['authorization']
  if (authHeader !== undefined) {
    jwtToken = authHeader.split(' ')[1]
  } else {
    return response.status(401).json('Invalid JWT Token')
  }

  jwt.verify(jwtToken, 'MY_SECRET_TOKEN', (payload, error) => {
    if (error) {
      response.status(401).json('Invalid JWT Token')
    } else {
      request.username = payload.username
      next()
    }
  })
}

// users Transactions

app.post('/transactions', authenticationToken, async (request, response) => {
  const {type, category, amount, date, description} = request.body

  
  const createTransactionsQuery = `
    INSERT INTO  
      transactions (type, category, amount, date, description) 
    VALUES (?, ?, ?, ?, ?)`

  try {
    const dbResponse = await db.run(createTransactionsQuery, [
      type,
      category,
      amount,
      date,
      description,
    ])
    const newTransactionId = dbResponse.lastID 
    response.send(`Created new Transaction with ID: ${newTransactionId}`)
  } catch (error) {
    console.error(`Error creating transaction: ${error.message}`)
    response.status(500).send('Internal Server Error')
  }
})

// get all transcations

app.get('/transactions', async (request, response) => {
  const selectTransctionsQuery = `
    SELECT 
      * 
    FROM 
      transactions
    LIMIT 10
  `
  const dbResponse = await db.all(selectTransctionsQuery)
  response.send(dbResponse)
})

// get one transcation on Id

app.get('/transactions/:id', async (request, response) => {
  const {id} = request.params
  const selectTransctionsQuery = `
    SELECT 
      * 
    FROM 
      transactions
    WHERE 
      id = ${id}
  `
  const dbResponse = await db.get(selectTransctionsQuery)
  response.send(dbResponse)
})

// update query

app.put('/transactions/:id', async (request, response) => {
  const {id} = request.params
  const {type, category, amount, date, description} = request.body

  const updateTransactionQuery = `
    UPDATE 
      transactions 
    SET 
      type = ?, 
      category = ?, 
      amount = ?, 
      date = ?, 
      description = ? 
    WHERE 
      id = ?`

  try {
    const result = await db.run(updateTransactionQuery, [
      type,
      category,
      amount,
      date,
      description,
      id,
    ])

    if (result.changes === 0) {
      // If no rows were updated, it means the transaction does not exist
      return response.status(404).send('Transaction not found')
    }

    response.send('Transaction Updated Successfully')
  } catch (error) {
    console.error(`Error updating transaction: ${error.message}`)
    response.status(404).send('Internal Server Error')
  }
})

// delete Query

app.delete('/transactions/:id', async (request, response) => {
  const {id} = request.params
  const deleteTransactionQuery = `
    SELECT 
      * 
    FROM 
      transactions 
    WHERE 
      id = ${id}
  `
  await db.run(deleteTransactionQuery)
  response.send('Transaction Deleted Successfully')
})

module.exports = app
