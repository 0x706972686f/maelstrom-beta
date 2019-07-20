"""
Malware Sample Uploader

Creates a simple flask page for uploading files, then display and downloading them.
"""

import os
import json
import hashlib
import pyminizip
import uuid
import socket
import ssl
import pythonwhois
import urllib.request
import datetime
from flask import Flask, request, redirect, url_for, render_template, send_from_directory
from app import app
from werkzeug.utils import secure_filename
from urllib.parse import urlparse
from time import gmtime, strftime
from app.fileanalysis import fileAnalysis, exeAnalysis
from app.headlesschrome import headlesschrome,hostinformation 

__author__ = "Sean Breen"
__copyright__ = "Copyright (C) 2019"
__credits__ = ["Sean Breen"]
__license__ = "MIT License"
__version__ = "2.0.0"
__maintainer__ = "Sean B"
__email__ = "sean@shadow.engineering"


"""
Future Functionality:
    -Push JSON into SQLAlchemy database
    -Fix error handling, make it more robust
    -Increase functionality of static analysis
    -Finish API, including ability to push/query
"""



"""
Function: index
Description:
        This function displays the index jinja2 template page
"""
@app.route('/')
@app.route('/index')
def index():
        return render_template('index.html')


"""
Function: about
Description:
        This function displays the about jinja2 template page
"""
@app.route('/about')
def about():
        return render_template('about.html')

"""
Function: create_dictionary
Description: 
        This function creates a dictionary that is used for each row in the samples.html page

Input:     filename (str)   - The name of the file 
Output:    d (dict)         - The dictionary to populate the table
"""
def create_dictionary(filename):
        d = {}
        f=os.path.join(app.config['TEMP_FOLDER'], filename)
        
        # Determining each attribute for the fields, then populate the dictionary 
        fileinfo = os.stat(f)
        filesize=str(fileinfo.st_size)
        d['date'] = strftime("%Y-%m-%d %H:%M:%S", gmtime())
        d['filename'] = filename
        d['zipfile'] = filename + '.zip'
        d['md5sum'] = hashlib.md5(open(f,'rb').read()).hexdigest()
        d['filesize'] = filesize
        return(d)

"""
Function: create_json
Description:
        This will create, or update the json file that stores all the attributes of files.
        It's used to populate the samples.html page.

Input:      filename (str)    - The name of the file
Output:     None
"""
def create_json(filename):
        # File to Store Content
        store = os.path.join(app.root_path, 'store.json')

        # To create a valid json file, we basically need a dictionary of dictionaries
        tmp = {}
        tmp[filename] = create_dictionary(filename)
        
        # Retrieve and Update JSON file
        if os.stat(store).st_size > 0:
                with open(store,'r') as f:
                        content = json.load(f)
                        f.close()
                with open(store,'w') as f:
                        content.update(tmp)
                        output = json.dumps(content, indent=4)
                        f.write(output)
                        f.close()
        
        # Create JSON file if it doesn't exist
        else:
                with open(store,'r+') as f:
                        output = json.dumps(tmp, indent=4)
                        f.write(output)
                        f.close()


"""
Function: zip_upload
Description:
        This function writes the uploaded file to a temporary directory, then creates a password protected zip file for download.

Input:      filename (str) - name of file that's being uploaded
Output:     None
"""
def zip_upload(filename):
        zipname = filename + '.zip'
        zippass = 'infected'
        upload = os.path.join(app.config['TEMP_FOLDER'], filename)
        output = os.path.join(app.config['UPLOAD_FOLDER'], zipname)
        pyminizip.compress(upload, None, output, zippass, 0)


"""
Function: delete_temp
Description:
        This function deletes the raw, uploaded file to save space.

Input:      filename (str) - name of the file that's stored in the /tmp folder
Output:     None
"""
def delete_temp(filename):
        upload = os.path.join(app.config['TEMP_FOLDER'], filename)
        if os.path.exists(upload):
                try:
                        os.remove(upload)
                except OSError as e:
                        pass

"""
Function: denied_websites
Description:
        With the functionality to now browse to websites, it's possible for flask to navigate to the flask app, or attempt to browse locally. 
        This is an attempt to block some of the more common methods. I should add more for encoded methods, but I'm trying not to blow it out too much.
        I'd normally pass it through some sort of filter function, but a lot of the dodgy websites that people will lookup might use those methods,
        which will throw exceptions

Input:      url (str) - url of the website to look up
Output:     char
"""
def denied_websites(url):
        DENIED_WEBSITES=set(['localhost','127.0.0.1','..','::1','10.','169.254.','172.16.','192.0.0.','192.88.99.','192.168.','224.','255.255.255.255'])
        return '.' in url and url.split('/',1)[0].lower() in DENIED_WEBSITES

"""
Function: static_file_analysis
Description:
        I created a class which does static file analysis of files, it offers a ton more functionality, including yara rule checking, clamav results,
        and more. It's not all implemented here, this is just a small sample for initial testing, it can be expanded out later.

Input:      upload (str) - name and filepath of the uploaded file to examine
Output:     None
"""
def static_file_analysis(upload):
        json_output = {}
        f = fileAnalysis(upload)

        json_output['filename'] = f.filename
        json_output['fileextension'] = f.fileextension
        json_output['filesizebytes'] = f.filesize
        json_output['filesizehuman'] = f.get_filesizehuman()
        json_output['md5sum'] = f.md5hash
        json_output['sha256sum'] = f.sha256hash
   
        metadata = f.get_filemetadata()
   
        # Skipping the starting metadata items, which show where the file is running on disk
        m_skipstart = {k: metadata[k] for k in list(metadata)[6:]}

        for k_m, v_m in m_skipstart.items():
                json_output[k_m] = v_m

        #vt = virustotal(VIRUSTOTALAPI)
        #vtjson = vt.submitmd5(f.md5hash)

        outputjson = 'app/uploads/' + f.md5hash + '.json'
        with open(outputjson, 'w') as res:
                json.dump(json_output, res,indent=4)
                res.close()





"""
Function serialiser
Description:
        Replaces all datetime.datetime objects in JSON data with the string equivalent

Input:  o (datetime.datetime) - 
Output: o.__str__() (str) -
"""
def serialiser(o):
        if isinstance(o, datetime.datetime):
                return o.__str__()

"""
Function: browse_site
Description:
        Creates a headless chrome driver instance, and navigates to a page. Attempts to take a screenshot, and retrieve the URL.

Input:  url (str) - the url to navigate to
        url_uuid (str) - a uuid of the url, used for identifying the screenshot with the url
        mobile (bool) - a boolean to identify whether the page should be viewed as a Desktop Chrome agent, or Mobile Chrome Agent
Output:
"""
def browse_site(url,url_uuid,mobile=False):
        result_dict = {}
    
        if mobile:
            screenshot_path = url_uuid + '_m.png'
        else:
            screenshot_path = url_uuid + '_d.png'


        hc = headlesschrome(url, mobile)
        hc.get_page()
        pageurl = hc.get_currenturl()
        pagetitle = hc.get_pagetitle()
        useragent = hc.get_useragent()
        # Known Bug in v73 of Chrome and Headless Chrome - can't take screenshots :(
        hc.get_pagescreenshot()
        hc.set_closesession()

        result_dict['title'] = pagetitle
        result_dict['finalurl'] = pageurl
        result_dict['useragent']  = useragent
        result_dict['screenshot'] = screenshot_path 

        return result_dict


"""
Function: Website_Analysis
Description:
        Writes a JSON file of the results from browse_site(), including paths to screenshots

Input:  url (str) - the String
        urluuid (str) - the UUID of the string
Output: None
"""
def website_analysis(url,urluuid):
        json_output = {}
        desktop = {}
        mobile = {}

        host_info = hostinformation(url)

        json_output['url'] = url
        json_output['ipaddress'] = host_info.get_ipaddress
        json_output['uuid'] = urluuid
        json_output['date'] = strftime("%Y-%m-%d %H:%M:%S", gmtime())

        json_output['domain_whois'] = host_info.get_whois()
        # When doing an IP lookup, we need to add http to the start for the urlparse to identify it as the netloc
        json_output['ip_whois'] = host_info.get_ipwhois()
        json_output['http_headers'] = host_info.get_httpheaders()
        json_output['ssl_certificate'] = host_info.get_sslcertificate()
    
        json_output['desktop'] = browse_site(url,urluuid)
        json_output['mobile'] = browse_site(url,urluuid,mobile=True)


        outputjson = 'app/websites/' + urluuid + '.json'
        with open(outputjson, 'w') as res:
                # Need to add the default = str because of python whois - it returns the dates as a datetime.datetime object (instead of converting to string)
                json.dump(json_output, res, indent=4, default=serialiser)
                #json.dump(json_output, res, indent=4)
                res.close()


"""
Celery
"""
@celery.task(bind=True)
def long_task(self):
        verb = ['Starting Up', 'Booting', 'Repairing', 'Loading', 'Checking']
        adjective = ['master', 'radiant', 'silent', 'harmonic', 'fast']
        noun = ['solar array', 'particle reshaper', 'cosmic ray', 'orbiter', 'bit']
        message = ''
        total = random.randint(10,50)
        for i in range(total):
                if not message or random.random() < 0.25:
                        message = '{0} {1} {2}...'.format(random.choice(verb), random.choice(adjective), random.choice(noun))
                self.update_state(state='PROGRESS', meta={'current': i, 'total': total, 'status': message})
                time.sleep(1)
        return {'current': 100, 'total': 100, 'status': 'Task Completed', 'result': 42}

@app.route('/longtask', methods=['POST'])
def longtask():
        task = long_task.apply_async()
        return jsonify({}), 202, {'Location': url_for('taskstatus', task_id=task.id)}

@app.route('/status/<task_id>')
        task = long_task.AsyncResult(task_id)
        if task.state == 'PENDING':
                #job did not start yet
                response = {
                        'state': task.state,
                        'current': 0,
                        'total': 1,
                        'status': 'Pending...'
                }
        elif task.state != 'FAILURE':
                response = {
                        'state': task.state,
                        'current': task.info.get('current', 0),
                        'total': task.info.get('total', 1),
                        'status': task.info.get('status', '')
                }
                if 'result' in task.info:
                        response['result'] = task.info['result']
        else:
                response = {
                        'state': task.state,
                        'current': 1,
                        'total': 1,
                        'status': str(task.info),
                }
        return jsonify(response)
"""
Function: uploader
Description:
        Primary function that decides what to do. If a file is uploaded, then it'll upload the file, zip it, and undertake the analysis.
        If a website is provided it'll create two headless chrome instances, one for browsing as a mobile phone, one for browsing as a 
        desktop instance, and record the results for analysis.

Input:      None
Output:     Redirection to /samples page, or updated index.html page with template

"""
@app.route('/uploader', methods= ['GET','POST'])
def uploader():
        if request.method == 'POST':
                if request.form['button'] == 'upload':
                    if 'file' not in request.files:
                            return render_template('index.html',error='No File Part')
                    f = request.files['file']
                    if f.filename == '':
                            return render_template('index.html',error='Empty Filename')
                    if f:
                            filename = secure_filename(f.filename)
                            dst = os.path.join(app.config['TEMP_FOLDER'], filename)
                            f.save(dst)
                            static_file_analysis(dst)
                            zip_upload(filename)
                            create_json(filename)
                            delete_temp(filename)
                            return redirect('/samples', code=302)
                    else: 
                            return render_template('index.html',error='The upload failed')
                if request.form['button'] == 'scan':
                    """
                    We should have some sort of form validation in here, using WTForms or similar to stop attempts of XSS/CSRQ and the like,
                    but because a lot of these submissions are anticipated to have some encoding that would trigger and therefor not get run
                    I'm going to create a simple custom filter looking for users attempting to exploit the host itself.
                    """
                    url = request.form['url']
                    if not url:
                            return render_template('index.html',error='No URL Provided')
                    if url and denied_websites(url):
                            return render_template('index.html',error="Invalid URL Provided")
                    if url:
                            fullurl = "http://{}".format(url)
                            urluuid = str(uuid.uuid3(uuid.NAMESPACE_DNS, fullurl))
                            website_analysis(fullurl,urluuid)
                            redirecturl = '/webanalysis/' + urluuid
                            return redirect(redirecturl, code=302)
                    else:
                            return render_template('index.html',error='Invalid input was provided')

"""
Function: uploaded_file
Description:
        Used by flask for linking to uploaded files.

Input:      filename (str)  - The name of the file that's been uploaded
Output:     url string of path
"""
@app.route('/uploads/<filename>')
def uploaded_file(filename):
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


"""
Function: sort_json
Description:
        Sorts the JSON store file, so that when you browse samples.html, the newest samples are at the top (rather than the bottom)

Input: content (str) - the content of the json store
Output: sortedcontent (str) - the sorted json store, reversed
"""
def sort_json(content):
        reverse = sorted(content.keys(),reverse=False)
        sortedcontent = {k: content[k] for k in reverse}

        return sortedcontent

"""
Function: read_jsonstore
Description:
        Reads in the JSON that's used to store information relating to uploaded files.

Input:      store (str) - the filepath of the store to read
Output:     Content (dict) - Content read in from store.json
"""
def read_jsonstore(store):
        with open(store,'r') as f:
                content = json.load(f)
                f.close()

        return content
 
"""
Function: samples
Description:
        Displays the samples.html page, a table of all current samples that have been uploaded.
        This populates a ninja2 template with the upload time, file name, file hash, and md5sum.

        The filename links to the filename, while the md5sum links to the virustotal page of the md5sum

Input:      None
Output:     Ninja2 template of samples.html
"""
@app.route('/samples')
def samples():
        samples = []

        store = os.path.join(app.root_path, 'store.json')
        unsorted = read_jsonstore(store)
        content = sort_json(unsorted)

        # Reads the JSON, which is a dictionary of dictionaries, and appends a key for the file path
        for key, value in content.items():
                value['path'] = url_for('uploaded_file', filename=value['zipfile'])
                samples.append(value)
        
        return render_template('samples.html',samples=samples)


"""
Function: webanalysis
Description:

Input:  uuid (str) - the UUID of the webpage, used for the json store
Output: Jinja2 template of websites.html
"""
@app.route('/webanalysis/<uuid>')
def webanalysis(uuid):
        f = 'websites/' + uuid + '.json'
        store = os.path.join(app.root_path, f)
        content = read_jsonstore(store)

        return render_template('websites.html',values=content)


"""
Function: fileanalysis
Description:
        Returns a webpage that displays the static analysis results of an upload.

Input: md5sum (str) - the md5sum of the file to analyse
Output: Jinja2 template of analysis.html
"""
@app.route('/fileanalysis/<md5sum>')
def fileanalysis(md5sum):
    f = 'uploads/' + md5sum + '.json'
    store = os.path.join(app.root_path, f)
    #filename = 'uploads/afaf2cdf9981342c494b28630608f74a.json'
    content = read_jsonstore(store)
    return render_template('analysis.html',values=content)

"""
Future API Implementation

@app.route('/api/v1.0/file/<str:md5sum>', methods=['GET'])
def api_filemd5sum():
    pass


/api/v1.0/file/<str:md5sum>
/api/v1.0/web/<str:uuid>
"""
