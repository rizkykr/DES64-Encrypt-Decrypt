<?php
/**
 * Cryptography DES (Data Encryption Standard) with Flat PHP
 * Created by Rizky Kurniawan Ritonga (https://rizkykr.com)
 */
class CryptoDES{
	private $log;
	//TABEL SOURCE ENKRIPSI
	private $l0idx = array(58,50,42,34,26,18,10,2,60,52,44,36,28,20,12,4,62,54,46,38,30,22,14,6,64,56,48,40,32,24,16,8);
	private $r0idx = array(57,49,41,33,25,17,9,1,59,51,43,35,27,19,11,3,61,53,45,37,29,21,13,5,63,55,47,39,31,23,15,7);
	private $c0idx = array(57,49,41,33,25,17,9,1,58,50,42,34,26,18,10,2,59,51,43,35,27,19,11,3,60,52,44,36);
	private $d0idx = array(63,55,47,39,31,23,15,7,62,54,46,38,30,22,14,6,61,53,45,37,29,21,13,5,28,20,12,4);
	private $lsi = array(1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1);
	private $tblippc2 = array(14,17,11,24,1,5,3,28,15,6,21,10,23,19,12,4,26,8,16,7,27,20,13,2,41,52,31,37,47,55,30,40,51,45,33,48,44,49,39,56,34,53,46,42,50,36,29,32);
	private $tblekspansi = array(32,1,2,3,4,5,4,5,6,7,8,9,8,9,10,11,12,13,12,13,14,15,16,17,16,17,18,19,20,21,20,21,22,23,24,25,24,25,26,27,28,29,28,29,30,31,32,1);
	private $bigsbox = array('1110','0100','1101','0001','0010','1111','1011','1000','0011','1010','0110','1100','0101','1001','0000','0111','0000','1111','0111','0100','1110','0010','1101','0001','1010','0110','1100','1011','1001','0101','0011','1000','0100','0001','1110','1000','1101','0110','0010','1011','1111','1100','1001','0111','0011','1010','0101','0000','1111','1100','1000','0010','0100','1001','0001','0111','0101','1011','0011','1110','1010','0000','0110','1101','1111','0001','1000','1110','0110','1011','0011','0100','1001','0111','0010','1101','1100','0000','0101','1010','0011','1101','0100','0111','1111','0010','1000','1110','1100','0000','0001','1010','0110','1001','1011','0101','0000','1110','0111','1011','1010','0100','1101','0001','0101','1000','1100','0110','1001','0011','0010','1111','1101','1000','1010','0001','0011','1111','0100','0010','1011','0110','0111','1100','0000','0101','1110','1001','1010','0000','1001','1110','0110','0011','1111','0101','0001','1101','1100','0111','1011','0100','0010','1000','1101','0111','0000','1001','0011','0100','0110','1010','0010','1000','0101','1110','1100','1011','1111','0001','1101','0110','0100','1001','1000','1111','0011','0000','1011','0001','0010','1100','0101','1010','1110','0111','0001','1010','1101','0000','0110','1001','1000','0111','0100','1111','1110','0011','1011','0101','0010','1100','0111','1101','1110','0011','0000','0110','1001','1010','0001','0010','1000','0101','1011','1100','0100','1111','1101','1000','1011','0101','0110','1111','0000','0011','0100','0111','0010','1100','0001','1010','1110','1001','1010','0110','1001','0000','1100','1011','0111','1101','1111','0001','0011','1110','0101','0010','1000','0100','0011','1111','0000','0110','1010','0001','1101','1000','1001','0100','0101','1011','1100','0111','0010','1110','0010','1100','0100','0001','0111','1010','1011','0110','1000','0101','0011','1111','1101','0000','1110','1001','1110','1011','0010','1100','0100','0111','1101','0001','0101','0000','1111','1010','0011','1001','1000','0110','0100','0010','0001','1011','1010','1101','0111','1000','1111','1001','1100','0101','0110','0011','0000','1110','1011','1000','1100','0111','0001','1110','0010','1101','0110','1111','0000','1001','1010','0100','0101','0011','1100','0001','1010','1111','1001','0010','0110','1000','0000','1101','0011','0100','1110','0111','0101','1011','1010','1111','0100','0010','0111','1100','1001','0101','0110','0001','1101','1110','0000','1011','0011','1000','1001','1110','1111','0101','0010','1000','1100','0011','0111','0000','0100','1010','0001','1101','1011','0110','0100','0011','0010','1100','1001','0101','1111','1010','1011','1110','0001','0111','0110','0000','1000','1101','0100','1011','0010','1110','1111','0000','1000','1101','0011','1100','1001','0111','0101','1010','0110','0001','1101','0000','1011','0111','0100','1001','0001','1010','1110','0011','0101','1100','0010','1111','1000','0110','0001','0100','1011','1101','1100','0011','0111','1110','1010','1111','0110','1000','0000','0101','1001','0010','0110','1011','1101','1000','0001','0100','1010','0111','1001','0101','0000','1111','1110','0010','0011','1100','1101','0010','1000','0100','0110','1111','1011','0001','1010','1001','0011','1110','0101','0000','1100','0111','0001','1111','1101','1000','1010','0011','0111','0100','1100','0101','0110','1011','0000','1110','1001','0010','0111','1011','0100','0001','1001','1100','1110','0010','0000','0110','1010','1101','1111','0011','0101','1000','0010','0001','1110','0111','0100','1010','1000','1101','1111','1100','1001','0000','0011','0101','0110','1011');
	private $sboxatas = array('0000'=>2,'0001'=>3,'0010'=>4,'0011'=>5,'0100'=>6,'0101'=>7,'0110'=>8,'0111'=>9,'1000'=>10,'1001'=>11,'1010'=>12,'1011'=>13,'1100'=>14,'1101'=>15,'1110'=>16,'1111'=>17);
	private $sboxkiri = array('00'=>0,'01'=>1,'10'=>2,'11'=>3);
	private $pbox = array(16,7,20,21,29,12,28,17,1,15,23,26,5,18,31,10,2,8,24,14,32,27,3,9,19,13,30,6,22,11,4,25);
	private $tblipmin1 = array(40,8,48,16,56,24,64,32,39,7,47,15,55,23,63,31,38,6,46,14,54,22,62,30,37,5,45,13,53,21,61,29,36,4,44,12,52,20,60,28,35,3,43,11,51,19,59,27,34,2,42,10,50,18,58,26,33,1,41,9,49,17,57,25);

	function __construct($debugmode=0){
		$this->log = ($debugmode==0) ? 0 : 1;
	}
	//untuk keperluan DEV
	function consolelog($data){
		$output = $data;
		if(is_array($output))
			$output = implode( ',', $output);
		echo ($this->log==1) ? "<script>console.log( 'Debug Objects: " . $output . "' );</script>" : "";
	}
	//ekstra : concat text
	function concatenateBIN($val){
		$dt = "";
		for ($i=0; $i < count($val); $i++) { 
			$dt .= $val[$i];
		}
		return $dt;
	}
	function alatxor($val1,$val2){
		return ($val1==$val2) ? "0" : "1";
	}
	function pecahtxt($text,$split){
		$array = array();
		for ($i = 0; $i < strlen($text);){
			$array[] = substr($text, $i, $split);
			$i += $split;
		}
		return $array;
	}

	//Konversi Setiap Teks menjadi Satu kesatuan Biner di Array
	function konversitobiner($val){
		$ncurtxt = strlen($val);
		for ($i=0; $i < (8-$ncurtxt); $i++) { 
			$val .= "#";
		}
		$explain = str_split($val);
		$konv = array();
		for ($i=0; $i < count($explain); $i++) {
			//bulatkan biner ke 8 karakter
			$dt = decbin(ord($explain[$i]));
			$caddzero = 8-strlen($dt);
			$addzerobin = "";
			$whl = 1;
			while ($whl <= $caddzero) {
				$addzerobin .= "0";
				$whl++;
			}
			array_push($konv,$addzerobin.$dt);
		}
		return $konv;
	}
	//Initian Permutasi Berdasarkan Array
	function IPdt($v,$idx){
		$arrIP = array();
		for ($i=0; $i < count($idx); $i++) {
			array_push($arrIP,$v[$idx[$i]-1]);
		}
		return $arrIP;
	}
	//Left Shift
	function lshift($val,$lshift){
		return substr($val,$lshift).substr($val,0,$lshift);
	}

	function enkripsiDES($val,$key){
		// 1. Konversi Plainteks dan Kunci ke Biner
		$konvplain = $this->konversitobiner($val);
		$konvkey = $this->konversitobiner($key);

		// 2. Lakukan Initial Permutasi pada Plainteks
		$kp = $this->concatenateBIN($konvplain);
		$l0 = $this->IPdt($kp,$this->l0idx);
		$r0 = $this->IPdt($kp,$this->r0idx);

		// 3. Lakukan Initial Permutasi pada Key
		$kk = $this->concatenateBIN($konvkey);
		$c0 = $this->IPdt($kk,$this->c0idx);
		$d0 = $this->IPdt($kk,$this->d0idx);

		// 4. Lakukan Pergeseran pada Hasil Permutasi Key c0 dan d0
		$lc = array();//Data C1 sd C16 : arr => 0
		$ld = array();//Data D1 sd D16 : arr => 0
		$temp_clshift = implode("",$c0);
		$temp_dlshift = implode("",$d0);
		for ($i=0; $i < 16; $i++) {
			$dc = $this->lshift($temp_clshift,$this->lsi[$i]);
			$dd = $this->lshift($temp_dlshift,$this->lsi[$i]);
			array_push($lc,$dc);array_push($ld,$dd);
			$temp_clshift = $dc;$temp_dlshift = $dd;
		}
		// 5. Lakukan Initial Permutasi Compression 2 PC-2 pada gabungan CiDi
		$kpc2 = array(); //Data K1-K16 : arr => 0
		for ($i=0; $i < 16; $i++){
			array_push($kpc2, implode('',$this->IPdt($lc[$i].$ld[$i],$this->tblippc2)));
		}

		$sboxdata1 = array_chunk($this->bigsbox, ceil(count($this->bigsbox) / 8));

		$temp_L = $this->concatenateBIN($l0);
		$temp_R = $this->concatenateBIN($r0);
		$temp_L_arr = array();
		$FINALR = array();

		for ($i=0; $i < 16; $i++){
			$curlitidx = $i;
			$litcur = "Literasi : ".($i+1);
			$this->consolelog($litcur);
			$this->consolelog($litcur." = TEMPORARY L = ".$temp_L);

			//Ekspansi Data
			$initE = implode('',$this->IPdt($temp_R,$this->tblekspansi));
			$temp_xor = "";
			for ($b=0; $b < strlen($initE); $b++){
				$temp_xor .= $this->alatxor($initE[$b],$kpc2[$i][$b]);
			}
			$this->consolelog($litcur." = Ekspansi Data = ".$temp_xor);

			//Fungsi S-Box
			$Asplit = $this->pecahtxt($temp_xor,6);
			$B = array();
			$sbxid = 0;
			while ($sbxid < 8) {
				$vH = $this->sboxatas[substr($Asplit[$sbxid],1,4)];
				$idxvH = array_search(substr($Asplit[$sbxid],1,4),array_keys($this->sboxatas))+2;
				$sbox = array_chunk($sboxdata1[$sbxid], ceil(count($sboxdata1[$sbxid]) / 4));
				$vV = array_search(substr($Asplit[$sbxid],0,1).substr($Asplit[$sbxid],-	1),array_keys($this->sboxkiri));
				array_push($B,$sbox[$vV][$idxvH-2]);
				$sbxid = $sbxid + 1;
			}
			$this->consolelog($litcur." = Fungsi S-Box = ". $this->concatenateBIN($B));

			//Permutasi P-Box Vector
			$PB = implode('',$this->IPdt($this->concatenateBIN($B),$this->pbox));
			$this->consolelog($litcur." = Permutasi P-Box Vector = ".$PB);

			//Literasi XOR
			$temp_xor_R = "";
			for ($b=0; $b < strlen($PB); $b++) {
				$temp_xor_R .= $this->alatxor($temp_L[$b],$PB[$b]);
			}
			$this->consolelog($litcur." = Literasi XOR Akhir = ".$temp_xor_R);
			array_push($FINALR,$temp_xor_R);

			// Literasi 1 L0; Literasi 2 R0; Literasi 3-16 R1-15
			$temp_R = $temp_xor_R;
			$temp_L = ($curlitidx == 0) ? $this->concatenateBIN($r0) : $FINALR[$curlitidx-1];
			array_push($temp_L_arr,$temp_L);
		}

		// 7. Proses Invers Ip-1 langsung lakukan Proses Konversi Chipper
		$r16l16 = $FINALR[15].$FINALR[14];
		$hasilakhirinvers = $this->IPdt($r16l16,$this->tblipmin1);
		$pecahperdelapanchipper = array_chunk($hasilakhirinvers, ceil(count($hasilakhirinvers) / 8));
		$desimalakhir = array();
		$CHIPPER = "";
		for ($i=0; $i < count($pecahperdelapanchipper); $i++){
			$slsh = ($i==7) ? "" : "/" ;
			$CHIPPER .= chr(bindec($this->concatenateBIN($pecahperdelapanchipper[$i])));
		}
		return base64_encode($CHIPPER);
	}
	function dekripsiDES($val,$key){
		// 1. Konversi Plainteks dan Kunci ke Biner
		$val = base64_decode($val);
		$konvplain = $this->konversitobiner($val);
		$konvkey = $this->konversitobiner($key);

		// 2. Lakukan Initial Permutasi pada Plainteks
		$kp = $this->concatenateBIN($konvplain);
		$l0 = $this->IPdt($kp,$this->l0idx);
		$r0 = $this->IPdt($kp,$this->r0idx);

		// 3. Lakukan Initial Permutasi pada Key
		$kk = $this->concatenateBIN($konvkey);
		$c0 = $this->IPdt($kk,$this->c0idx);
		$d0 = $this->IPdt($kk,$this->d0idx);

		// 4. Lakukan Pergeseran pada Hasil Permutasi Key c0 dan d0
		$lc = array();//Data C1 sd C16 : arr => 0
		$ld = array();//Data D1 sd D16 : arr => 0
		$temp_clshift = implode("",$c0);
		$temp_dlshift = implode("",$d0);
		for ($i=0; $i < 16; $i++) {
			$dc = $this->lshift($temp_clshift,$this->lsi[$i]);
			$dd = $this->lshift($temp_dlshift,$this->lsi[$i]);
			array_push($lc,$dc);array_push($ld,$dd);
			$temp_clshift = $dc;$temp_dlshift = $dd;
		}
		// 5. Lakukan Initial Permutasi Compression 2 PC-2 pada gabungan CiDi
		$kpc2 = array(); //Data K1-K16 : arr => 0
		for ($i=0; $i < 16; $i++){
			array_push($kpc2, implode('',$this->IPdt($lc[$i].$ld[$i],$this->tblippc2)));
		}

		$sboxdata1 = array_chunk($this->bigsbox, ceil(count($this->bigsbox) / 8));

		$temp_L = $this->concatenateBIN($l0);
		$temp_R = $this->concatenateBIN($r0);
		$temp_L_arr = array();
		$FINALR = array();

		for ($i=0; $i < 16; $i++){
			$curlitidx = $i;
			$litcur = "Literasi : ".($i+1);
			$this->consolelog($litcur);
			$this->consolelog($litcur." = TEMPORARY L = ".$temp_L);

			//Ekspansi Data
			$initE = implode('',$this->IPdt($temp_R,$this->tblekspansi));
			$temp_xor = "";
			for ($b=0; $b < strlen($initE); $b++){
				$temp_xor .= $this->alatxor($initE[$b],$kpc2[(15-$i)][$b]);
			}
			$this->consolelog($litcur." = Ekspansi Data = ".$temp_xor);

			//Fungsi S-Box
			$Asplit = $this->pecahtxt($temp_xor,6);
			$B = array();
			$sbxid = 0;
			while ($sbxid < 8) {
				$vH = $this->sboxatas[substr($Asplit[$sbxid],1,4)];
				$idxvH = array_search(substr($Asplit[$sbxid],1,4),array_keys($this->sboxatas))+2;
				$sbox = array_chunk($sboxdata1[$sbxid], ceil(count($sboxdata1[$sbxid]) / 4));
				$vV = array_search(substr($Asplit[$sbxid],0,1).substr($Asplit[$sbxid],-	1),array_keys($this->sboxkiri));
				array_push($B,$sbox[$vV][$idxvH-2]);
				$sbxid = $sbxid + 1;
			}
			$this->consolelog($litcur." = Fungsi S-Box = ". $this->concatenateBIN($B));

			//Permutasi P-Box Vector
			$PB = implode('',$this->IPdt($this->concatenateBIN($B),$this->pbox));
			$this->consolelog($litcur." = Permutasi P-Box Vector = ".$PB);

			//Literasi XOR
			$temp_xor_R = "";
			for ($b=0; $b < strlen($PB); $b++) {
				$temp_xor_R .= $this->alatxor($temp_L[$b],$PB[$b]);
			}
			$this->consolelog($litcur." = Literasi XOR Akhir = ".$temp_xor_R);
			array_push($FINALR,$temp_xor_R);

			// Literasi 1 L0; Literasi 2 R0; Literasi 3-16 R1-15
			$temp_R = $temp_xor_R;
			$temp_L = ($curlitidx == 0) ? $this->concatenateBIN($r0) : $FINALR[$curlitidx-1];
			array_push($temp_L_arr,$temp_L);
		}

		// 7. Proses Invers Ip-1 langsung lakukan Proses Konversi Chipper
		$r16l16 = $FINALR[15].$FINALR[14];
		$hasilakhirinvers = $this->IPdt($r16l16,$this->tblipmin1);
		$pecahperdelapanchipper = array_chunk($hasilakhirinvers, ceil(count($hasilakhirinvers) / 8));
		$desimalakhir = array();
		$CHIPPER = "";
		for ($i=0; $i < count($pecahperdelapanchipper); $i++){
			$CHIPPER .= chr(bindec($this->concatenateBIN($pecahperdelapanchipper[$i])));
		}
		return str_replace("#", "", $CHIPPER);
	}
}
