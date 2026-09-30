`protocol1-vectors.json` is the frozen protocol-1 conformance data from
https://github.com/bojieli/queqiao at commit
9229f7730225f6dfc30a2d81f9cabfdf8039147e, copied unchanged under its MIT license
(included as `QUEQIAO-LICENSE`). Values described as identities are synthetic.

The native outbound's tests exercise all frame-header and UDP PACKET acceptance/rejection
vectors. The UDP resume and FEC/coded-datagram vector sections remain out of scope
and are not claimed as tested. The implementation does not import the upstream Go module or client.
