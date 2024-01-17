import express from "express";
const app = express();
import dotenv from "dotenv";
import mongoose from "mongoose";
dotenv.config();
import jwt from "jsonwebtoken";
import { nanoid } from "nanoid";
import cors from "cors";
import admin from "firebase-admin";
import aws from "aws-sdk";
const PORT = process.env.PORT || 3000;
const DB_LOCATION = process.env.DB_LOCATION;
import serviceAccountKey from "./blog-app-931ce-firebase-adminsdk-d2bc4-9a12eb4328.json" assert { type: "json" };
import Comment from "./Schema/Comment.js";
import { getAuth } from "firebase-admin/auth";

admin.initializeApp({ credential: admin.credential.cert(serviceAccountKey) });
app.use(express.json());
app.use(cors());

import bcrypt from "bcrypt";
import User from "./Schema/User.js";
import Blog from "./Schema/Blog.js";
import Notification from "./Schema/Notification.js";
let emailRegex = /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/; // regex for email
let passwordRegex = /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{6,20}$/; // regex for password
(async function main() {
  mongoose.connect(DB_LOCATION);
})()
  .then((result) => {
    console.log("DB CONNECTED");
  })
  .catch((err) => {
    console.log(err);
  });

//setting up s3 buckt
const s3 = new aws.S3({
  region: "ap-south-1",
  accessKeyId: process.env.AWS_ACCESS_KEY,
  secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
});
let generateUploadUrl = () => {
  let date = new Date();
  let imageName = `${nanoid()}-${date.getTime()}.jpeg`;

  return s3.getSignedUrlPromise("putObject", {
    Bucket: "major-mern-blog",
    Key: imageName,
    Expires: 1000,
    ContentType: "image/jpeg",
  });
};
const verifyJwt = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (token == null) {
    return res.status(401).json({ error: "No access token" });
  }
  jwt.verify(token, process.env.SECRET_ACCESS_KEY, (err, user) => {
    if (err) res.status(403).json({ error: "Access token in invalid" });
    req.user = user.id;
    next();
  });
};

async function generateUsername(email) {
  let username = email.split("@")[0];
  let userExists = await User.exists({ "personal_info.username": username });
  userExists ? (username += nanoid().substring(0, 5)) : "";
  return username;
}
//upload image
app.get("/get-upload-url", (req, res) => {
  generateUploadUrl().then((url) => {
    res.status(200).json({ uploadedUrl: url });
  });
});
const formatDatatoSend = (user) => {
  const access_token = jwt.sign(
    { id: user._id },
    process.env.SECRET_ACCESS_KEY
  );
  return {
    access_token,
    profile_img: user.personal_info.profile_img,
    username: user.personal_info.username,
    fullname: user.personal_info.fullname,
  };
};

app.post("/signup", async (req, res) => {
  let { fullname, email = "", password } = req.body;
  console.log(req.body);
  if (fullname.length < 3) {
    return res
      .status(403)
      .json({ error: "Fullname must be at least 3 letters long" });
  }

  if (!emailRegex.test(email)) {
    return res
      .status(403)
      .json({ error: "Please enter a valid email address" });
  }
  if (!passwordRegex.test(password)) {
    return res.status(403).json({
      error:
        "Password should be 6 to 20 letters long including a numeric,uppercase & a lowercase ",
    });
  }
  bcrypt.hash(password, 10, async (err, hash) => {
    if (err) console.log(err);
    let username = await generateUsername(email);
    let user = new User({
      personal_info: { fullname, email, password: hash, username },
    });
    await user
      .save()
      .then((u) => res.status(200).json(formatDatatoSend(u)))
      .catch((e) => {
        if (e.code == 11000) {
          return res.status(500).json({ error: "Email already exists" });
        }
        return res.status(500).json({ error: e.message });
      });
  });
});

app.post("/signin", (req, res) => {
  let { email, password } = req.body;
  User.findOne({ "personal_info.email": email })
    .then((user) => {
      if (!user) {
        return res.status(403).json({ error: "Email not found" });
      }
      bcrypt.compare(password, user.personal_info.password, (err, result) => {
        if (err) {
          return res
            .status(403)
            .json({ error: "Error occured while logging in. Try again" });
        }
        if (!result) {
          return res.status(403).json({ error: "Wrong password" });
        } else {
          return res.status(200).json(formatDatatoSend(user));
        }
      });
    })
    .catch((e) => {
      res.status(500).json({ error: e.message });
    });
});
app.post("/google-auth", async (req, res) => {
  const { access_token } = req.body;

  getAuth()
    .verifyIdToken(access_token)
    .then(async (decodedUser) => {
      let { email, name, picture } = decodedUser;
      picture = picture.replace("s96-c", "s384-c");
      let user = await User.findOne({ "personal_info.email": email })
        .select(
          "personal_info.fullname personal_info.username personal_info.profile_img google_auth"
        )
        .then((result) => {
          console.log(result);

          return result || null;
        })
        .catch((err) => {
          res.status(500).json({ error: err.message });
        });
      if (user) {
        if (!user.google_auth) {
          //user exixst but not with google auth so tell him to login with password instead
          return res.status(403).json({
            error: "This email already exists, please login using password",
          });
        }
      } else {
        // user already exixt with googleauth so login
        let username = await generateUsername(email);
        user = new User({
          personal_info: {
            fullname: name,
            email,
            profile_img: picture,
            username,
          },
          google_auth: true,
        });
        await user
          .save()
          .then((u) => {
            user = u;
          })
          .catch((err) => res.status(500).json({ error: err.message }));
      }
      return res.status(200).json(formatDatatoSend(user));
    })
    .catch((err) => res.status(500).json({ error: err.message }));
});

//trending blogs
app.get("/trending-blogs", (req, res) => {
  let maxLimit = 5;
  Blog.find({ draft: false })
    .populate(
      "author",
      "personal_info.profile_img personal_info.username personal_info.fullname -_id"
    )
    .sort({
      "activity.total_read": -1,
      "activity.total_likes": -1,
      publishedAt: -1,
    })
    .select("blog_id title publishedAt -_id")
    .limit(maxLimit)
    .then((blogs) => {
      return res.status(200).json({ blogs });
    })
    .catch((err) => {
      return res.status(500).json({ error: err.message });
    });
});

//searchblogs
app.post("/search-blogs", (req, res) => {
  let { tag, query, author, page, limit, eleminateBlogId } = req.body;
  let findQuery;
  if (tag) {
    findQuery = { tags: tag, draft: false, blog_id: { $ne: eleminateBlogId } };
  } else if (query) {
    findQuery = { draft: false, title: new RegExp(query, "i") };
  } else if (author) {
    findQuery = { author, draft: false };
  }

  let maxLimit = limit ? limit : 2;
  Blog.find(findQuery)
    .populate(
      "author",
      "personal_info.profile_img personal_info.username personal_info.fullname -_id"
    )
    .sort({ publishedAt: -1 })
    .skip((page - 1) * maxLimit)
    .select("blog_id title des banner activity tags publishedAt -_id")
    .limit(maxLimit)
    .then((blogs) => {
      return res.status(200).json({ blogs });
    })
    .catch((err) => {
      console.log(err);
      res.status(500).json({ error: err.message });
    });
});

//blogs

app.post("/latest-blogs", (req, res) => {
  let { page } = req.body;
  let maxLimit = 5;
  Blog.find({ draft: false })
    .populate(
      "author",
      "personal_info.profile_img personal_info.username personal_info.fullname -_id"
    )
    .sort({ publishedAt: -1 })
    .select("blog_id title des banner activity tags publishedAt -_id")
    .skip((page - 1) * maxLimit)
    .limit(maxLimit)
    .then((blogs) => {
      return res.status(200).json({ blogs });
    })
    .catch((err) => {
      console.log(err);
      res.status(500).json({ error: err.message });
    });
});

app.post("/search-blogs-count", (req, res) => {
  let { tag, query, author } = req.body;
  let findQuery;
  if (tag) {
    findQuery = { tags: tag, draft: false };
  } else if (query) {
    findQuery = { draft: false, title: new RegExp(query, "i") };
  } else if (author) {
    findQuery = { author, draft: false };
  }

  Blog.countDocuments(findQuery)
    .then((count) => {
      return res.status(200).json({ totalDocs: count });
    })
    .catch((e) => {
      console.log(e.message);
      return res.status(500).json({ error: e.message });
    });
});
app.post("/search-users", (req, res) => {
  let { query } = req.body;
  User.find({ "personal_info.username": new RegExp(query, "i") })
    .limit(50)
    .select(
      "personal_info.username personal_info.fullname personal_info.profile_img -_id"
    )
    .then((users) => {
      return res.status(200).json({ users });
    })
    .catch((err) => {
      return res.status(500).json({ error: err.message });
    });
});

app.post("/get-profile", (req, res) => {
  let { username } = req.body;
  User.findOne({ "personal_info.username": username })
    .select("-personal_info.password -google_auth -updateAt -blogs")
    .then((user) => {
      return res.status(200).json(user);
    })
    .catch((e) => {
      return res.status(500).json({ error: e.message });
    });
});

app.post("/all-latest-blogs-count", (req, res) => {
  Blog.countDocuments({ draft: false })
    .then((count) => {
      return res.status(200).json({ totalDocs: count });
    })
    .catch((e) => {
      console.log(e.message);
      return res.status(500).json({ error: e.message });
    });
});

app.post("/create-blog", verifyJwt, (req, res) => {
  let authorId = req.user;
  console.log(authorId);

  let { title, des, banner, tags, content, draft, id } = req.body;
  if (!title.length) {
    return res.json(403).json({ error: "You must provide a valid title" });
  }
  if (!draft) {
    if (!des.length || des.length > 250) {
      return res.json(430).json({
        error: "You must Provide a blog description under 250 characters",
      });
    }
    if (!banner.length) {
      return res
        .status(403)
        .json({ error: "You mus provide a banner to publish" });
    }
    if (!content.blocks.length) {
      return res
        .status(403)
        .json({ error: "There must be content to publish" });
    }
    if (!tags.length || tags.length > 10) {
      return res
        .status(403)
        .json({ error: "please provide tags between 1 to 10" });
    }
    tags = tags.map((tag) => tag.toLowerCase());
  }

  let blog_id =
    id ||
    title
      .replace(/[^a-zA-Z0-9]/g, "  ")
      .replace(/\s+/g, "-")
      .trim() + nanoid(8);

  if (id) {
    Blog.findOneAndUpdate(
      { blog_id },
      { title, des, banner, content, tags, draft: draft ? draft : false }
    )
      .then(() => {
        return res.status(200).json({ id: blog_id });
      })
      .catch((e) => {
        return res.status(500).json({ error: e.message });
      });
  } else {
    let blog = new Blog({
      blog_id,
      title,
      banner,
      des,
      content,
      tags,
      author: authorId,
      draft: Boolean(draft),
    });
    blog
      .save()
      .then(() => {
        let incrementVal = draft ? 0 : 1;
        User.findOneAndUpdate(
          { _id: authorId },
          {
            $inc: { "account_info.total_posts": incrementVal },
            $push: { blogs: blog._id },
          }
        )
          .then((user) => {
            return res.status(200).json({ id: blog.blog_id });
          })
          .catch((err) => {
            return res
              .status(500)
              .json({ error: "Failed to update total post number" });
          });
      })
      .catch((err) => {
        return res.status(500).json({ error: err.message });
      });
  }

  console.log(blog_id, tags);
});

app.post("/get-blog", (req, res) => {
  let { blog_id, draft, mode } = req.body;
  let incrementVal = mode != "edit" ? 1 : 0;

  Blog.findOneAndUpdate(
    { blog_id },
    { $inc: { "activity.total_reads": incrementVal } }
  )
    .populate(
      "author",
      "personal_info.fullname personal_info.username personal_info.profile_img"
    )
    .select("title des content banner activity publishedAt blog_id tags")
    .then((blog) => {
      res.status(200).json({ blog });
      User.findOneAndUpdate(
        { "personal_info.username": blog.author.personal_info.username },
        { $inc: { "account_info.total_reads": incrementVal } }
      ).catch((e) => {
        return res.status(500).json({ error: e.message });
      });
      if (blog.draft$ && !draft) {
        return res.status(500).json({ error: "'you cant access draft blogs" });
      }
    })
    .catch((e) => {
      res.status(500).json({ error: e.message });
    });
});
app.post("/like-blog", verifyJwt, (req, res) => {
  let user_id = req.user;
  let { _id, isLikedByUser } = req.body;
  let incrementVal = !isLikedByUser ? 1 : -1;
  Blog.findOneAndUpdate(
    { _id },
    { $inc: { "activity.total_likes": incrementVal } }
  ).then((blog) => {
    if (!isLikedByUser) {
      let like = new Notification({
        type: "like",
        blog: _id,
        notification_for: blog.author,
        user: user_id,
      });
      like.save().then((notification) => {
        return res.status(200).json({ liked_by_user: true });
      });
    } else {
      Notification.findOneAndDelete({ user: user_id, blog: _id, type: "like" })
        .then((data) => {
          return res.status(200).json({ liked_by_user: false });
        })
        .catch((e) => {
          return res.status(500).json({ error: e.message });
        });
    }
  });
});

app.post("/isLiked-by-user", verifyJwt, (req, res) => {
  let user_id = req.user;
  let { _id } = req.body;
  Notification.exists({ user: user_id, type: "like", blog: _id })
    .then((result) => {
      return res.status(200).json({ result });
    })
    .catch((e) => {
      return res.status(500).json({ error: e.message });
    });
});
app.post("/add-comment", verifyJwt, (req, res) => {
  let user_id = req.user;
  let { _id, comment, blog_author } = req.body;
  if (!comment.length) {
    return res.status(403).json({ error: "Write something to post a comment" });
  }
  let commentObj = new Comment({
    blog_id: _id,
    blog_author,
    comment,
    commented_by: user_id,
  });
  commentObj.save().then((commentFile) => {
    let { comment, commentedAt, children } = commentFile;
    Blog.findOneAndUpdate(
      { _id },
      {
        $push: { comments: commentFile._id },
        $inc: { "activity.total_comments": 1 },
        "activity.total_parent_comments": 1,
      }
    ).then((blog) => {
      console.log("New comment created");
    });

    let notificaionObj = {
      type: "comment",
      blog: _id,
      notification_for: blog_author,
      user: user_id,
      comment: commentFile._id,
    };
    new Notification(notificaionObj).save().then((notification) => {
      console.log("New notification created");
    });

    return res.status(200).json({
      comment,
      commentedAt,
      _id: commentFile._id,
      user_id,
      children,
    });
  });
});
app.post("/get-blog-comments",(req,res)=>{
  let {blog_id,skip}=req.body;
  let maxLimit=5
  Comment.find({blog_id,isReply:false}).populate("commented_by","personal_info.username personal_info.fullname personal_info.profile_img")
  .skip(skip)
  .limit(maxLimit)
  .sort({'commentedAt':-1})
  .then(comment=>{
    return res.status(200).json(comment)
  })
  .catch((e)=>{
    console.log(e.message)
    return res.json({"error":e.message}).status(500)
  })

})

app.listen(PORT, () => {
  console.log(`Server is listening to the port ${PORT}`);
});
