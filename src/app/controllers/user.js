// import conexao from "../data/conexao.js";

// class controUser {
//   async create (req, res)  {
//   {
//         const sql = "SELECT * FROM users";
    
//         try {
//             const data = await new Promise((resolve, reject) => {
//                 conexao.query(sql, (err, results) => {
//                     if (err) reject(err);
//                     else resolve(results);
//                 });
//             });
    
//             res.status(200).json(data);
//         } catch (err) {
//             res.status(500).json({ error: err.message });
//         }
//     };
// }
// }
// export default new controUser()
 