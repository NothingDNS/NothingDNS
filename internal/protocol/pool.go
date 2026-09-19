package protocol

import "sync"

var (
	wireNamePool = sync.Pool{
		New: func() any {
			wire := make([]byte, 0, MaxNameLength)
			return &wire
		},
	}

	questionPool = sync.Pool{
		New: func() any {
			return &Question{}
		},
	}

	resourceRecordPool = sync.Pool{
		New: func() any {
			return &ResourceRecord{}
		},
	}

	namePool = sync.Pool{
		New: func() any {
			return &Name{}
		},
	}

	rdataAPool          = sync.Pool{New: func() any { return &RDataA{} }}
	rdataAAAAPool       = sync.Pool{New: func() any { return &RDataAAAA{} }}
	rdataCNAMEPool      = sync.Pool{New: func() any { return &RDataCNAME{} }}
	rdataDNAMEPool      = sync.Pool{New: func() any { return &RDataDNAME{} }}
	rdataNSPool         = sync.Pool{New: func() any { return &RDataNS{} }}
	rdataPTRPool        = sync.Pool{New: func() any { return &RDataPTR{} }}
	rdataMXPool         = sync.Pool{New: func() any { return &RDataMX{} }}
	rdataTXTPool        = sync.Pool{New: func() any { return &RDataTXT{} }}
	rdataSOAPool        = sync.Pool{New: func() any { return &RDataSOA{} }}
	rdataSRVPool        = sync.Pool{New: func() any { return &RDataSRV{} }}
	rdataHINFOPool      = sync.Pool{New: func() any { return &RDataHINFO{} }}
	rdataRPPool         = sync.Pool{New: func() any { return &RDataRP{} }}
	rdataAFSDBPool      = sync.Pool{New: func() any { return &RDataAFSDB{} }}
	rdataKXPool         = sync.Pool{New: func() any { return &RDataKX{} }}
	rdataURIPool        = sync.Pool{New: func() any { return &RDataURI{} }}
	rdataNAPTRPool      = sync.Pool{New: func() any { return &RDataNAPTR{} }}
	rdataCAAPool        = sync.Pool{New: func() any { return &RDataCAA{} }}
	rdataCERTPool       = sync.Pool{New: func() any { return &RDataCERT{} }}
	rdataOPENPGPKEYPool = sync.Pool{New: func() any { return &RDataOPENPGPKEY{} }}
	rdataDHCIDPool      = sync.Pool{New: func() any { return &RDataDHCID{} }}
	rdataSSHFPPool      = sync.Pool{New: func() any { return &RDataSSHFP{} }}
	rdataTLSAPool       = sync.Pool{New: func() any { return &RDataTLSA{} }}
	rdataOPTPool        = sync.Pool{New: func() any { return &RDataOPT{} }}
	rdataSVCBPool       = sync.Pool{New: func() any { return &RDataSVCB{} }}
	rdataHTTPSPool      = sync.Pool{New: func() any { return &RDataHTTPS{} }}
)

func acquireWireNameBuffer() []byte {
	return (*wireNamePool.Get().(*[]byte))[:0]
}

func releaseWireNameBuffer(wire *[]byte) {
	if wire == nil {
		return
	}
	for i := range *wire {
		(*wire)[i] = 0
	}
	*wire = (*wire)[:0]
	wireNamePool.Put(wire)
}

func acquireName() *Name {
	n := namePool.Get().(*Name)
	n.wire = nil
	n.stringCache.Store(nil)
	return n
}

func acquireQuestion() *Question {
	q := questionPool.Get().(*Question)
	q.Name = nil
	q.QType = 0
	q.QClass = 0
	return q
}

func acquireResourceRecord() *ResourceRecord {
	rr := resourceRecordPool.Get().(*ResourceRecord)
	rr.Name = nil
	rr.Type = 0
	rr.Class = 0
	rr.TTL = 0
	rr.Data = nil
	return rr
}

func releaseRData(data RData) {
	switch r := data.(type) {
	case *RDataA:
		*r = RDataA{}
		rdataAPool.Put(r)
	case *RDataAAAA:
		*r = RDataAAAA{}
		rdataAAAAPool.Put(r)
	case *RDataCNAME:
		if r.CName != nil {
			r.CName.Release()
		}
		r.CName = nil
		rdataCNAMEPool.Put(r)
	case *RDataDNAME:
		if r.DName != nil {
			r.DName.Release()
		}
		r.DName = nil
		rdataDNAMEPool.Put(r)
	case *RDataNS:
		if r.NSDName != nil {
			r.NSDName.Release()
		}
		r.NSDName = nil
		rdataNSPool.Put(r)
	case *RDataPTR:
		if r.PtrDName != nil {
			r.PtrDName.Release()
		}
		r.PtrDName = nil
		rdataPTRPool.Put(r)
	case *RDataMX:
		if r.Exchange != nil {
			r.Exchange.Release()
		}
		r.Exchange = nil
		r.Preference = 0
		rdataMXPool.Put(r)
	case *RDataTXT:
		for i := range r.Strings {
			r.Strings[i] = ""
		}
		r.Strings = r.Strings[:0]
		rdataTXTPool.Put(r)
	case *RDataSOA:
		if r.MName != nil {
			r.MName.Release()
		}
		if r.RName != nil {
			r.RName.Release()
		}
		*r = RDataSOA{}
		rdataSOAPool.Put(r)
	case *RDataSRV:
		if r.Target != nil {
			r.Target.Release()
		}
		*r = RDataSRV{}
		rdataSRVPool.Put(r)
	case *RDataHINFO:
		*r = RDataHINFO{}
		rdataHINFOPool.Put(r)
	case *RDataRP:
		if r.MBox != nil {
			r.MBox.Release()
		}
		if r.Txt != nil {
			r.Txt.Release()
		}
		*r = RDataRP{}
		rdataRPPool.Put(r)
	case *RDataAFSDB:
		if r.Hostname != nil {
			r.Hostname.Release()
		}
		*r = RDataAFSDB{}
		rdataAFSDBPool.Put(r)
	case *RDataKX:
		if r.Exchanger != nil {
			r.Exchanger.Release()
		}
		*r = RDataKX{}
		rdataKXPool.Put(r)
	case *RDataURI:
		*r = RDataURI{}
		rdataURIPool.Put(r)
	case *RDataNAPTR:
		if r.Replacement != nil {
			r.Replacement.Release()
		}
		*r = RDataNAPTR{}
		rdataNAPTRPool.Put(r)
	case *RDataCAA:
		*r = RDataCAA{}
		rdataCAAPool.Put(r)
	case *RDataCERT:
		r.Certificate = r.Certificate[:0]
		*r = RDataCERT{}
		rdataCERTPool.Put(r)
	case *RDataOPENPGPKEY:
		r.PublicKey = r.PublicKey[:0]
		*r = RDataOPENPGPKEY{}
		rdataOPENPGPKEYPool.Put(r)
	case *RDataDHCID:
		r.Data = r.Data[:0]
		*r = RDataDHCID{}
		rdataDHCIDPool.Put(r)
	case *RDataSSHFP:
		r.Fingerprint = r.Fingerprint[:0]
		*r = RDataSSHFP{}
		rdataSSHFPPool.Put(r)
	case *RDataTLSA:
		r.Certificate = r.Certificate[:0]
		*r = RDataTLSA{}
		rdataTLSAPool.Put(r)
	case *RDataOPT:
		for i := range r.Options {
			r.Options[i].Data = nil
		}
		r.Options = r.Options[:0]
		rdataOPTPool.Put(r)
	case *RDataSVCB:
		if r.Target != nil {
			r.Target.Release()
		}
		for i := range r.Params {
			r.Params[i].Value = nil
		}
		*r = RDataSVCB{}
		rdataSVCBPool.Put(r)
	case *RDataHTTPS:
		if r.Target != nil {
			r.Target.Release()
		}
		for i := range r.Params {
			r.Params[i].Value = nil
		}
		*r = RDataHTTPS{}
		rdataHTTPSPool.Put(r)
	}
}

func pooledRData(rrtype uint16) RData {
	switch rrtype {
	case TypeA:
		return rdataAPool.Get().(*RDataA)
	case TypeAAAA:
		return rdataAAAAPool.Get().(*RDataAAAA)
	case TypeCNAME:
		return rdataCNAMEPool.Get().(*RDataCNAME)
	case TypeDNAME:
		return rdataDNAMEPool.Get().(*RDataDNAME)
	case TypeNS:
		return rdataNSPool.Get().(*RDataNS)
	case TypePTR:
		return rdataPTRPool.Get().(*RDataPTR)
	case TypeMX:
		return rdataMXPool.Get().(*RDataMX)
	case TypeTXT:
		return rdataTXTPool.Get().(*RDataTXT)
	case TypeSOA:
		return rdataSOAPool.Get().(*RDataSOA)
	case TypeSRV:
		return rdataSRVPool.Get().(*RDataSRV)
	case TypeHINFO:
		return rdataHINFOPool.Get().(*RDataHINFO)
	case TypeRP:
		return rdataRPPool.Get().(*RDataRP)
	case TypeAFSDB:
		return rdataAFSDBPool.Get().(*RDataAFSDB)
	case TypeKX:
		return rdataKXPool.Get().(*RDataKX)
	case TypeURI:
		return rdataURIPool.Get().(*RDataURI)
	case TypeNAPTR:
		return rdataNAPTRPool.Get().(*RDataNAPTR)
	case TypeCAA:
		return rdataCAAPool.Get().(*RDataCAA)
	case TypeCERT:
		return rdataCERTPool.Get().(*RDataCERT)
	case TypeOPENPGPKEY:
		return rdataOPENPGPKEYPool.Get().(*RDataOPENPGPKEY)
	case TypeDHCID:
		return rdataDHCIDPool.Get().(*RDataDHCID)
	case TypeSSHFP:
		return rdataSSHFPPool.Get().(*RDataSSHFP)
	case TypeTLSA:
		return rdataTLSAPool.Get().(*RDataTLSA)
	case TypeOPT:
		return rdataOPTPool.Get().(*RDataOPT)
	case TypeSVCB:
		return rdataSVCBPool.Get().(*RDataSVCB)
	case TypeHTTPS:
		return rdataHTTPSPool.Get().(*RDataHTTPS)
	default:
		return nil
	}
}
