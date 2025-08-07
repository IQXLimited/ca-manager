export namespace main {
	
	export class CAInput {
	    country: string;
	    state: string;
	    locality: string;
	    org: string;
	    commonName: string;
	    expiryDays: number;
	
	    static createFrom(source: any = {}) {
	        return new CAInput(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.country = source["country"];
	        this.state = source["state"];
	        this.locality = source["locality"];
	        this.org = source["org"];
	        this.commonName = source["commonName"];
	        this.expiryDays = source["expiryDays"];
	    }
	}
	export class CertDetails {
	    subject: string;
	    issuer: string;
	    validFrom: string;
	    validUntil: string;
	    serialNumber: string;
	    ipAddresses: string[];
	    dnsNames: string[];
	
	    static createFrom(source: any = {}) {
	        return new CertDetails(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.subject = source["subject"];
	        this.issuer = source["issuer"];
	        this.validFrom = source["validFrom"];
	        this.validUntil = source["validUntil"];
	        this.serialNumber = source["serialNumber"];
	        this.ipAddresses = source["ipAddresses"];
	        this.dnsNames = source["dnsNames"];
	    }
	}

}

