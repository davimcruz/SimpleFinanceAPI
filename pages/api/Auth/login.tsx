// Importando as dependências necessárias
import express from "express"
import mysql, { MysqlError } from "mysql"
import jwt, { Secret } from "jsonwebtoken"
import { serialize } from "cookie"
import { dbConfig } from "@/config/dbConfig"

// Criando uma instância do Express
const app = express()

// Configurando o middleware CORS
import cors from "cors"
app.use(cors())

// Configurando o middleware para fazer o parser do corpo das requisições como JSON
app.use(express.json())

// Criando uma conexão com o banco de dados
const pool = mysql.createPool(dbConfig)

// Definindo a rota para a autenticação
app.post("/api/Auth/login", (req, res) => {
  const { email, password } = req.body

  try {
    pool.getConnection((err: MysqlError, connection) => {
      if (err) {
        console.error("Erro ao conectar ao banco de dados:", err)
        return res
          .status(500)
          .json({ error: "Erro ao processar a requisição." })
      }

      const query = "SELECT id, email, senha FROM usuarios WHERE email = ?"
      connection.query(query, [email], (error, results) => {
        connection.release()

        if (error) {
          console.error("Erro ao executar consulta:", error)
          return res
            .status(500)
            .json({ error: "Erro ao processar a requisição." })
        }

        if (results.length === 0) {
          return res.status(401).json({ error: "Email não registrado." })
        }

        const user = results[0]
        if (user.senha !== password) {
          return res.status(401).json({ error: "Senha incorreta." })
        }

        const token = jwt.sign(
          { email: user.email },
          process.env.JWT_SECRET as Secret,
          {
            expiresIn: "24h",
          }
        )

        const cookieToken = serialize("token", token, {
          httpOnly: true,
          sameSite: "none",
          secure: true,
          maxAge: 86400,
          path: "/",
        })

        const cookieEmail = serialize("email", user.email, {
          httpOnly: true,
          sameSite: "none",
          secure: true,
          maxAge: 86400,
          path: "/",
        })

        const cookieUserId = serialize("userId", user.id, {
          httpOnly: true,
          sameSite: "none",
          secure: true,
          maxAge: 86400,
          path: "/",
        })

        if (req.headers.origin) {
          res.setHeader("Access-Control-Allow-Origin", req.headers.origin)
        }

        res.setHeader("Set-Cookie", [cookieToken, cookieEmail, cookieUserId])

        return res.status(200).json({ message: "Login bem-sucedido." })
      })
    })
  } catch (error) {
    console.error("Erro:", error)
    return res.status(500).json({ error: "Erro ao processar a requisição." })
  }
})

// Iniciando o servidor
app.listen(3000, () => {
  console.log("Server is running on port 3000")
})
