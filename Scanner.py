import requests, re, urllib.parse
from bs4 import BeautifulSoup as beauty
class scanner:
	def __init__(self, url):
		self.session=requests.Session()
		self.targ_url=url
		self.targ_links=[]
		self.targ_links.append(url)

	def extract_links_from(self, url):
		res=self.session.get(url)
		return re.findall('(?:href=")(.*?)"',str(res.content))

	def crawl(self, url=None):
		if url==None:
			url=self.targ_url
		href_links=self.extract_links_from(url)
		for link in href_links:
			link=urllib.parse.urljoin(url, link)
			if len(self.targ_links)>=25:
				break
			if "#" in link:
				link=link.split("#")[0]
			if self.targ_url in link and link not in self.targ_links:
				self.targ_links.append(link)
				print(link)
				self.crawl(link)

	def extract_forms(self, url):
		res=self.session.get(url)
		parsed_html=beauty(res.content,features="html.parser")
		return parsed_html.findAll("form")

	def submit_form(self, form, value, url):
		action=form.get("action")
		post_url=urllib.parse.urljoin(url, action)
		method=form.get("method")
		input_lists=form.findAll("input")
		post_data={}
		for i in input_lists:
			input_name=i.get("name")
			input_type=i.get("type")
			input_value=i.get("value")
			if input_type=="text":
				input_value=value
			post_data[input_name]=input_value
		if method=="post":
			return self.session.post(post_url,data=post_data)
		else:
			return self.session.get(post_url,params=post_data)

	def run_scanner(self):
		for link in self.targ_links:
			forms=self.extract_forms(link)
			for form in forms:
				print("[+] Testing form in "+link)
				is_vuln=self.test_xss_in_forms(form, link)
				if is_vuln:
					print("\n\n[***] XSS vulnerability found in " + link + "in the following form")		
					print(form)
			if "=" in link:
				print("\n\n[+] Testing in "+link)
				is_vuln=self.test_xss_in_links(link)
				if is_vuln:
					print("[***] XSS vulnerability found in " + link)

	def test_xss_in_links(self, url):
		xss_script="<sCript>alert('test')</scriPt>"
		url=url.replace("=","="+xss_script)
		res=self.session.get(url)
		return xss_script in str(res.content)
		
	def test_xss_in_forms(self, form, url):
		xss_script="<sCript>alert('test')</scriPt>"
		res=self.submit_form(form, xss_script, url)
		return xss_script in str(res.content)


scan=scanner("")  # website link to be given as argument here
scan.crawl()
scan.run_scanner()