<?php
//php app/console decom:lock http://rubbish.ninja/composer.lock

namespace JingleJangle\DecomposerBundle\Command;

use Symfony\Bundle\FrameworkBundle\Command\ContainerAwareCommand;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

use Symfony\Component\DomCrawler\Crawler;

class DecomposerCommand extends ContainerAwareCommand
{
	private $lockJson; 
	private $lockFile; 
	private $tmpfile; 
	public $detailLinks; 
	public $CVElinks; 
	public $vulns; 
	public $results = []; 

	protected function configure()
	{
		$this
			->setName('decom:lock')
			->setDescription('Test a lock file')
			->addArgument('url', InputArgument::OPTIONAL, 'url to lock file to scan')
			->addOption('scan', null, InputOption::VALUE_NONE, 'scan for urls')
			;
	}

	protected function execute(InputInterface $input, OutputInterface $output)
	{
		$this->tmpfile = tempnam('/tmp/', 'scan.lock'); 
		$this->scanUrl = "https://security.sensiolabs.org/check_lock.html"; 
		$this->output = $output; 
		
		if ($input->getArgument('url')) {
			$this->getLockFile($input->getArgument('url'));
			$response = $this->uploadFile(); 
			$this->showVulnList($response);
		}

		if($input->getOption('scan')){ 
			$urls = $this->scan();
			foreach($urls as $url){ 
				try{ 
				$this->output->writeln("################SCANNING $url...");
				
				$this->getLockFile($url); 
				$response = $this->uploadFile(); 
				$this->showVulnList($response);
				}catch(\UnexpectedValueException $e){ 
					$this->output->writeln($e->getMessage());
				}
			}
		}
	}


	private function showVulnList($body){ 
		$crawler = new \Symfony\Component\DomCrawler\Crawler($body);
		$vulnerabilities = $crawler->filter('ol')->text();
		//$this->output->writeln($vulnerabilities); 
		$this->niceVuln = $vulnerabilities; 
		$lines = explode("\n", $vulnerabilities);
		$vulns = []; 
		foreach($lines as $l){ 
			$l=trim($l);
			if(!empty($l)){ 
				$vulns[] = $l; 
			}
		}
		//print_r($vulns);
		$this->vulns = $vulns; 


		$this->output->writeln("#Detail Links: "); 
		$this->detailLinks = $crawler
			->filterXpath('//ol/li/a')
			->extract(array('href'));
		foreach($this->detailLinks as $link){ 
			$this->output->writeln($link); 
		}



		$this->CVElinks = $crawler
			->filterXpath('//ol/li/small/a')
			->extract(array('href'));

		$this->output->writeln("#CVE Links: "); 
		foreach($this->CVElinks as $link){ 
			$this->output->writeln($link); 
		}
	}

	private function getLockFile($url){ 
		$this->url = $url;
		$this->output->writeln("Downloading $url");

		try { 

		$json = file_get_contents($this->url); 
		}catch(\Exception $e){ 
			$this->output->writeln("Caught exception, problem getting $url");
			throw new \UnexpectedValueException('Json lock file cannot be fetched'); 
		}

		if(json_decode($json)){ 
			$this->lockJson = $json;
			$this->lockFile = $json; 
			try { 
				file_put_contents($this->tmpfile, $json); 
			}catch(\Exception $e){ 
				$this->output->writeln("Caught exception, cannot create $this->tmpfile");
			}
			return true; 
		}	
		throw new \UnexpectedValueException('Json lock file cannot be decoded'); 
	}

	function getCurlValue($filename, $contentType, $postname)
	{
		if (function_exists('curl_file_create')) {
			return curl_file_create($filename, $contentType, $postname);
		}
		$value = "@{$filename};filename=" . $postname;
		if ($contentType) {
			$value .= ';type=' . $contentType;
		}

		return $value;
	}


	private function uploadFile(){ 
		$this->tmpfile; 
		$cfile = $this->getCurlValue($this->tmpfile,'text/json','composer.lock');
		$data = array('lock' => $cfile);
		$ch = curl_init();
		$options = array(CURLOPT_URL => $this->scanUrl, 
				CURLOPT_RETURNTRANSFER => true,
				CURLINFO_HEADER_OUT => true, 
				CURLOPT_HEADER => true, 
				CURLOPT_SSL_VERIFYPEER => false, 
				CURLOPT_POST => true,
				CURLOPT_POSTFIELDS => $data
				);
		curl_setopt_array($ch, $options);
		$result = curl_exec($ch);
		$header_info = curl_getinfo($ch,CURLINFO_HEADER_OUT);
		$header_size = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
		$header = substr($result, 0, $header_size);
		$body = substr($result, $header_size);
		curl_close($ch);
		return $body; 
	}

	function scan($start=0){ 
		$query = "site:www.*.*/composer.lock"; 	
		$url = "http://ajax.googleapis.com/ajax/services/search/web?v=1.0&rsz=large&start=$start&q=".urlencode($query);
		$body = file_get_contents($url);
		$json = json_decode($body);
		$results = $this->extractResults($json);
		return $results; 
	}

	private function extractResults($json){ 
			$matches = [];
			foreach($json->responseData->results as $row){ 
				$matches[] = $row->url;
			}
			return $matches; 
	}

	function __destruct(){
		if(file_exists($this->tmpfile)){ 
			unlink($this->tmpfile); 
		}
	}
}

