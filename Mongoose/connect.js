import mongoose from "mongoose";
import dotenv from "dotenv";

dotenv.config()

const username=process.env.USER_NAME;
const password =process.env.PASSWORD;

const DBclient=async()=>{
    try{
        await mongoose.connect(`mongodb+srv://${username}:${password}@cluster0.eqbprpg.mongodb.net/MarkdownViewer?retryWrites=true&w=majority`,{
            UseNewUrlParser:true
        })
        console.log("db connected")
    }catch(err){
        console.log(err)
    }
}

export default DBclient