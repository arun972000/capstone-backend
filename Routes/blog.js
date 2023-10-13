import express, { json } from "express"
import { BlogPost } from "../Mongoose/model.js";
import { v4 } from "uuid";
import { Error } from "mongoose";

const blogRoute = express.Router();

blogRoute.use(json())

blogRoute.get("/", async (req, res) => {
    try {
        const blogs = await BlogPost.find({});
        res.status(201).json(blogs)
    } catch (err) {
        res.status(500).send(err.message)
    }

})

blogRoute.post("/create", async (req, res) => {
    try {
        const { title, content, author, tags, imageUrl } = req.body;
        const newBlogPost = new BlogPost({
            title,
            content,
            author,
            tags,
            imageUrl,
            id: v4()
        });
        const savedBlogPost = await newBlogPost.save();

        res.status(201).json(savedBlogPost);
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'An error occurred while creating the blog post.' });
    }
})

blogRoute.put("/edit/:id", async (req, res) => {
    try {
        const { id } = req.params;
        const payload = req.body;
        const updateBlog = await BlogPost.updateOne({ id: id }, { $set: payload })
        res.status(201).json({ message: "updated" })
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'An error occurred while creating the blog post.' });
    }
})

blogRoute.get("/:id", async (req, res) => {
    try {
        const { id } = req.params;

        const singleBlog = await BlogPost.findOne({ id })
        res.status(201).json(singleBlog)
    } catch (err) {
        console.error(error);
        res.status(500).json({ error: 'An error occurred while creating the blog post.' });
    }
})

blogRoute.delete("/delete/:id", async (req, res) => {
    try {
        const { id } = req.params;

        const singleBlog = await BlogPost.deleteOne({ id })
        res.status(201).json("deleted")
    } catch (err) {
        console.error(error);
        res.status(500).json({ error: 'An error occurred while creating the blog post.' });
    }
})

blogRoute.get("/search/:name", async (req, res) => {
    try {
        const {name} = req.params; // Assuming you're passing the search value in the "value" query parameter
        const blogs = await BlogPost.find({ title: { $regex: new RegExp(name, 'i') } });
        res.status(200).json(blogs);
    } catch (err) {
        res.status(500).send(err.message);
    }
});

export default blogRoute;

