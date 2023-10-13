import mongoose from "mongoose";

const blogPostSchema = new mongoose.Schema({
    id: {
        type: String,
        required: true,
    },
    imageUrl:{
        type:String,
        required:true
    },
    title: {
        type: String,
        required: true,
    },
    content: {
        type: String,
        required: true,
    },
    author: {
        type: String,
        required: true,
    },
    date: {
        type: String,
        default: new Date(),
    },
    tags: [String],
    comments: [
        {
            user: String,
            text: String,
            date: {
                type: Date,
                default: Date.now,
            },
        },
    ],
});

const userSchema =new mongoose.Schema({
    id:{
        type:String,
        required:true
    },
    name:{
        type:String,
        required:true
    },
    email:{
        type:String,
        required:true
    },
    password:{
        type:String,
        required:true
    },
    resetPasswordToken:{
        type:String
        
    },
    
})



export const BlogPost = mongoose.model('BlogPost', blogPostSchema);
export const Usermodel = mongoose.model("user",userSchema)

