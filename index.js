import express, { json } from 'express';
import DBclient from './Mongoose/connect.js';
import blogRoute from './Routes/blog.js';
import cors from "cors"
import userRoutes from './Routes/user.js';

const app = express();

await DBclient()

app.use(cors({
    origin: "*",
}))

app.use(json())

app.use("/api/blog", blogRoute)
app.use("/api",userRoutes)


const PORT = process.env.PORT || 3000;

app.get('/', async (req, res) => {
    res.json({ status: true, message: "Our node.js app works" })
});

app.listen(PORT, () => console.log(`App listening at port ${PORT}`));