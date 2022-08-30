require 'glimmer-dsl-libui'
require 'thread'
include Glimmer
@runcheck=0

def eckisHashAlg(input)
	hashsize=64
	def sqmul(a, g ,p)
		cache=g
		a.chars.each_with_index do |x, i|
			if i!=0
				cache=(cache**2)%p
				cache=(cache*(g**a[x].to_i))%p
			end
		end
		return cache
	end
	input=input.bytes
	hashblocks=[[]]
	b=0 
	input.each do |x|
		if hashblocks[b].size < hashsize
			hashblocks[b].push(x)
		else
			hashblocks.push([])
			b+=1
			hashblocks[b].push(x)
		end
	end
	for x in 0..hashsize-hashblocks[b].size-1
		hashblocks[b].push(input[x%input.size])
	end
	blockcount=hashblocks.size
	for y in 0..10-blockcount do
		hashblocks.push(hashblocks[y])
	end
	hashblocks.each_with_index do |x, i|
		hashblocks[i]=x.rotate(i)
	end
	hashblocks.each_with_index do |x, i|
		x[(x[0]*i)%hashsize]=sqmul((x[2%hashsize]*input.size%hashsize).to_s(2), x[1], x[3%hashsize]+input.size%hashsize)   
		for y in 0..hashsize-1
			cache=x[(y+2)%hashsize]										
			x[(y+2)%hashsize]=((x[y]+ x[(y+1)%hashsize])*input.size+i**2)%123				
			x[y]=cache											
			x[y]=(x[(y)%hashsize] ^ x[(y+1)%hashsize]).to_s(2).to_i(2)					
		end
	end
	for x in 0..hashblocks.size-2 do
		for y in 0..hashsize-1
			hashblocks[0][y]=(hashblocks[0][y] ^ hashblocks[(x+1)][y]).to_s(2).to_i(2)
		end
	end
	(hashblocks[0]).each_with_index do |x, i|
		hashblocks[0][i]=x%123
		if hashblocks[0][i]<48
			hashblocks[0][i]+=48
		elsif hashblocks[0][i]>90 and hashblocks[0][i]<97
			hashblocks[0][i]-=6
		elsif hashblocks[0][i]>57 and hashblocks[0][i]<65
			hashblocks[0][i]+=7
		end
	end
	result=""
	hashblocks[0].each do |c|
		result+=c.chr
	end
	return result
end

def hashlist(password, layers)
	hashcache=password
	hashlist=[]
	layers.times do
		hashcache=eckisHashAlg(hashcache)
		hashlist.append(hashcache)
	end
	return hashlist
end

def encrypt(password, data)
	data=data.bytes
	size=data.length
	@progress=0

	layers=Math.log(size, 64).ceil-0
	@steps=layers+4
	
	salt=""
	64.times do
		salt+=rand(48..126).chr
	end
	hashlist=hashlist(password+salt, layers)

	@progress+=1
	@progress_bar.value=(@progress.to_f/@steps.to_f*100.to_f).round
	@progresstext.text="Encrypting base layer..."
	basehashbytes=eckisHashAlg(hashlist[hashlist.size-1]).bytes
	data.each_with_index do |current, n|
		data[n]=(current+(basehashbytes)[n%64])%255
	end

	hashlist.each_with_index do |x, i|
		@progress+=1
		@progress_bar.value=(@progress.to_f/@steps.to_f*100.to_f).round
		@progresstext.text="Encrypting higher layer #{i+1}/#{layers}..."
		datablockscache=[[]]
		b=0
		data.each_with_index do |y, c|
			if datablockscache[b].length < 64**(layers-i)
				datablockscache[b].push(y)
			else
				datablockscache.push([])
				b+=1
				datablockscache[b].push(y)
			end
		end
		datablockscache.each_with_index do |current, n|
			current.each_with_index do |character, m|
				datablockscache[n][m]=(character+(x.bytes)[n%64])%255
				datablockscache[n][m]=(datablockscache[n][m]+(hashlist[(i+1)%hashlist.size].bytes)[n%64])%255
			end
		end
		datablockscache.flatten!
		data=datablockscache
	end

	@progress+=1
	@progress_bar.value=(@progress.to_f/@steps.to_f*100.to_f).round
	@progresstext.text="Collecting data..."
	result=salt+" "
	data.each do |x|
		cryptchar=x.to_s(16)
		if cryptchar.length==1
			cryptchar="0"+cryptchar
		end
		result+=cryptchar
	end
	@progress+=1
	@progress_bar.value=(@progress.to_f/@steps.to_f*100.to_f).round
	@progresstext.text="Writing..."
	@cryptotext.text=result
	@progress+=1
	@progress_bar.value=(@progress.to_f/@steps.to_f*100.to_f).round	
	@progresstext.text="Successfully encrypted text!"
	@runcheck=0
end

def decrypt(password, data)
	data=data.split(" ")
	salt=data.shift
	data=data.first.scan(/../)
	data.each_with_index do |d,i|
		data[i]=d.to_i(16)
	end
	size=data.length
	
	@progress=0

	layers=Math.log(size, 64).ceil
	@steps=layers+3

	hashlist=hashlist(password+salt, layers)
	hashlist=hashlist.reverse

	hashlist.each_with_index do |x, i|
		@progress+=1
		@progress_bar.value=(@progress.to_f/@steps.to_f*100.to_f).round
		@progresstext.text="Decrypting higher layer #{i+1}/#{layers}..."
		datablockscache=[[]]
		b=0
		data.each_with_index do |y, c|
			if datablockscache[b].length < 64**(i+1)
				datablockscache[b].push(y)
			else
				datablockscache.push([])
				b+=1
				datablockscache[b].push(y)
			end
		end
		datablockscache.each_with_index do |current, n|
			current.each_with_index do |character, m|
				datablockscache[n][m]=datablockscache[n][m]-(x.bytes)[n%64]-(hashlist[(i+hashlist.size-1)%hashlist.size].bytes)[n%64]
				if datablockscache[n][m].negative?()	
					datablockscache[n][m]=255+datablockscache[n][m]
				end
			end
		end
		datablockscache.flatten!
		data=datablockscache
	end

	@progress+=1
	@progress_bar.value=(@progress.to_f/@steps.to_f*100.to_f).round
	@progresstext.text="Decrypting base layer..."
	basehashbytes=eckisHashAlg(hashlist[0]).bytes
	data.each_with_index do |current, n|
		data[n]=current-(basehashbytes)[n%64]
		if data[n].negative?()
			data[n]=255+data[n]
		end
	end

	@progress+=1
	@progress_bar.value=(@progress.to_f/@steps.to_f*100.to_f).round
	@progresstext.text="Collecting data..."
	@passwordcheck=0
	result=""
	data.each do |c|
		if (c.negative?() || c>127)
			@passwordcheck+=1
		else
			result+=c.chr
		end
	end
	if @passwordcheck==0
		@progress+=1
		@progress_bar.value=(@progress.to_f/@steps.to_f*100.to_f).round
		@progresstext.text="Succesfully decrypted text!"
		@cleartext.text=result
	else
		@progresstext.text="ERROR: Wrong password!"
	end

	@runcheck=0
end
			
window('H4shTexter', 1000, 400) {
	margined true
	group('H4shTexter for ASCII-encoded text by Leif-Erik Hallmann') {
		
		vertical_box {
			horizontal_box {
				group('CLEARTEXT:') {
					@cleartext = multiline_entry {
					}
				}
				vertical_box {
					stretchy false
					button(">>>ENCRYPT!>>>") {
						on_clicked do
							if @password.text==""	
								@progresstext.text="ERROR: Password empty!"		
							elsif (not (@cleartext.text.ascii_only?))
								@progresstext.text="ERROR: text contents are out of the ASCII-range!"
							elsif @cleartext.text.length < 2
								@progresstext.text="ERROR: Text contains less than two characters! Write at least two characters into the cleartext form first."
							else			
								if @runcheck==0
									@runcheck=1
									Thread.new do
										@progress_bar.value=0
										@progresstext.text="Starting..."
										data=@cleartext.text
										encrypt(@password.text, data)
									end
								end
							end
						end
					}
					group('PASSWORD:') {
						stretchy false	
						@password = entry {
						}
					}
					button("<<<DECRYPT!<<<") {
						
						on_clicked do
							if @password.text==""	
								@progresstext.text="ERROR: Password empty!"		
							elsif (not (@cryptotext.text.ascii_only?))
								@progresstext.text="ERROR: text contents are out of the ASCII-range!"
							elsif @cryptotext.text.length < 2
								@progresstext.text="ERROR: Text contains less than two characters! Write at least two characters in to the cleartext form first."
							else			
								if @runcheck==0
									@runcheck=1
									Thread.new do
										@progress_bar.value=0
										@progresstext.text="Starting..."
										data=@cryptotext.text
										decrypt(@password.text, data)
									end
								end
							end
						end
					}	
				}
				
				group('CRYPTOTEXT:') {
					@cryptotext = multiline_entry { 
					}
				}
			}
			
			@progresstext = label ('Ready'){stretchy false}
			@progress_bar = progress_bar {stretchy false}
		}
	}
}.show

